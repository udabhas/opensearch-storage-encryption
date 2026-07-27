/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.CryptoDirectoryFactory;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.niofs.CryptoBufferedIndexInput;
import org.opensearch.index.store.niofs.CryptoOutputStreamIndexOutput;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;
import org.opensearch.index.store.pool.Pool;
import org.opensearch.index.store.read_ahead.ReadaheadContext;
import org.opensearch.index.store.read_ahead.ReadaheadManager;
import org.opensearch.index.store.read_ahead.Worker;
import org.opensearch.index.store.read_ahead.impl.ReadaheadManagerImpl;

/**
 * A high-performance FSDirectory implementation that combines Direct I/O operations with encryption.
 *
 * <p>This directory provides:
 * <ul>
 * <li>Direct I/O operations bypassing the OS page cache for better memory control</li>
 * <li>Block-level caching with memory segment pools for efficient memory management</li>
 * <li>Transparent encryption/decryption using OpenSSL native implementations</li>
 * <li>Read-ahead optimizations for sequential access patterns</li>
 * <li>Automatic cache invalidation on file deletion</li>
 * </ul>
 *
 * <p>The directory uses {@link BufferIOWithCaching} for output operations which encrypts
 * data before writing to disk and caches plaintext blocks for read operations. Input
 * operations use {@link CachedMemorySegmentIndexInput} with a multi-level cache hierarchy
 * including {@link RadixBlockTable} for L1 caching.
 *
 * <p>Note: routing of small metadata files (e.g. segments_N and .si) to the NIO crypto path
 * is handled by {@link org.opensearch.index.store.hybrid.HybridCryptoDirectory} when this
 * directory is used under HYBRIDFS; files this directory receives directly are encrypted via
 * {@link BufferIOWithCaching}.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "uses custom DirectIO")
public class BufferPoolDirectory extends FSDirectory {
    private static final Logger LOGGER = LogManager.getLogger(BufferPoolDirectory.class);
    // BufferPoolDirectory is instantiated per shard, but the cache + pool are node-global singletons.
    // Guard so the telemetry thread starts exactly once per JVM, not per shard (would produce 200x
    // duplicate log lines on a node with ~200 shards).
    private static final java.util.concurrent.atomic.AtomicBoolean TELEMETRY_STARTED = new java.util.concurrent.atomic.AtomicBoolean(false);
    private final AtomicLong nextTempFileCounter = new AtomicLong();

    private final Pool<RefCountedByteBuffer> memorySegmentPool;
    private final BlockCache<RefCountedByteBuffer> blockCache;
    private final Worker readAheadworker;
    private final Provider provider;
    private final Path dirPath;
    private final byte[] masterKeyBytes;
    private final KeyResolver keyResolver;
    private final EncryptionMetadataCache encryptionMetadataCache;
    private final RadixBlockTableRegistry radixBlockTableRegistry;

    /**
     * Creates a new CryptoDirectIODirectory with the specified components.
     *
     * @param path the directory path
     * @param lockFactory the lock factory for coordinating access
     * @param provider the security provider for cryptographic operations
     * @param keyResolver resolver for encryption keys and initialization vectors
     * @param memorySegmentPool pool for managing off-heap memory segments
     * @param blockCache cache for storing decrypted blocks
     * @param blockLoader loader for reading blocks from storage
     * @param worker background worker for read-ahead operations
     * @param encryptionMetadataCache cache for encryption metadata
     * @param radixBlockTableRegistry registry for per-file L1 RadixBlockTable lifecycle management
     * @throws IOException if the directory cannot be created or accessed
     */
    public BufferPoolDirectory(
        Path path,
        LockFactory lockFactory,
        Provider provider,
        KeyResolver keyResolver,
        Pool<RefCountedByteBuffer> memorySegmentPool,
        BlockCache<RefCountedByteBuffer> blockCache,
        BlockLoader<RefCountedByteBuffer> blockLoader,
        Worker worker,
        EncryptionMetadataCache encryptionMetadataCache,
        RadixBlockTableRegistry radixBlockTableRegistry
    )
        throws IOException {
        super(path, lockFactory);
        this.memorySegmentPool = memorySegmentPool;
        this.blockCache = blockCache;
        this.readAheadworker = worker;
        this.provider = provider;
        this.dirPath = getDirectory();
        this.keyResolver = keyResolver;
        this.masterKeyBytes = keyResolver.getDataKey().getEncoded();
        this.encryptionMetadataCache = encryptionMetadataCache;
        this.radixBlockTableRegistry = radixBlockTableRegistry;

        // Emit BufferPool live state (cache + pool) to logs.
        if (TELEMETRY_STARTED.compareAndSet(false, true)) {
            startCacheStatsTelemetry();
        }
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        try {
            ensureOpen();
            ensureCanRead(name);

            Path file = dirPath.resolve(name);
            long rawFileSize = Files.size(file);
            if (rawFileSize == 0) {
                throw new IOException("Cannot open empty file with DirectIO: " + file);
            }

            // Routing by IOContext:
            // - MERGE: sequential bulk reads with occasional random access (term dict lookups).
            //   Use NIO decrypt for sequential reads; randomAccessSlice() uses block cache.
            // - READONCE: one-pass sequential streaming (snapshot source, recovery streaming).
            //   Use NIO decrypt with no cache — data is never re-read.
            // - DEFAULT: search queries and recovery source reads on started shards.
            //   Use full BufferPool (L1→L2→disk + read-ahead). Recovery source with DEFAULT
            //   reads the same files being searched, so caching them is not wasteful.
            if (context.context() == IOContext.Context.MERGE) {
                return openNIOInput(file, context, false);
            }
            if (isReadOnce(context)) {
                return openNIOInput(file, context, true);
            }

            // DEFAULT path: full block cache for search reads (and recovery source on started shards)
            long contentLength = calculateContentLengthWithValidation(file, rawFileSize);

            ReadaheadManager readAheadManager = new ReadaheadManagerImpl(readAheadworker, blockCache);
            ReadaheadContext readAheadContext = readAheadManager.register(file, contentLength);
            RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixBlockTable = radixBlockTableRegistry.acquire(file);

            return CachedMemorySegmentIndexInput
                .newInstance(
                    "CachedMemorySegmentIndexInput(path=\"" + file + "\")",
                    file,
                    contentLength,
                    blockCache,
                    readAheadManager,
                    readAheadContext,
                    radixBlockTable,
                    radixBlockTableRegistry
                );
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.INDEX_INPUT_ERROR);
            throw e;
        }
    }

    /**
     * Opens a file via the NIO decrypt path (CryptoBufferedIndexInput).
     * Sequential reads bypass the pool entirely. If {@code disableCache} is false,
     * randomAccessSlice() can still use the shared block cache for random reads.
     */
    private IndexInput openNIOInput(Path file, IOContext context, boolean disableCache) throws IOException {
        FileChannel fc = FileChannel.open(file, StandardOpenOption.READ);
        boolean success = false;
        try {
            BlockCache<RefCountedByteBuffer> cacheForRAS = disableCache ? null : blockCache;
            RadixBlockTableRegistry registryForRAS = disableCache ? null : radixBlockTableRegistry;

            IndexInput input = new CryptoBufferedIndexInput(
                "CryptoBufferedIndexInput(path=\"" + file + "\")",
                fc,
                context,
                this.keyResolver,
                file,
                this.encryptionMetadataCache,
                cacheForRAS,
                registryForRAS
            );
            success = true;
            return input;
        } finally {
            if (!success) {
                fc.close();
            }
        }
    }

    /** Check if this context represents a READONCE (sequential one-pass) read. */
    private static boolean isReadOnce(IOContext context) {
        return context == IOContext.READONCE;
    }

    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        try {
            ensureOpen();
            Path path = directory.resolve(name);
            OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

            // Use the non-caching encrypted output: encrypts data to disk without acquiring pool
            // segments or putting plaintext blocks into the cache. The read path fills the cache
            // on demand (first read after write pays a disk read + decrypt).
            // This eliminates pool exhaustion, cache thrashing, and GC storms during writes.
            return new CryptoOutputStreamIndexOutput(
                name,
                path,
                fos,
                this.keyResolver,
                this.provider,
                EncryptionMetadataTrailer.ALGORITHM_AES_256_GCM,
                path,
                this.encryptionMetadataCache
            );
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.INDEX_OUTPUT_ERROR);
            throw e;
        }
    }

    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        ensureOpen();
        String name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        return new CryptoOutputStreamIndexOutput(
            name,
            path,
            fos,
            this.keyResolver,
            this.provider,
            EncryptionMetadataTrailer.ALGORITHM_AES_256_GCM,
            path,
            this.encryptionMetadataCache
        );
    }

    // only close resources owned by this directory type.
    // the actual directory is closed only once (see HybridCryptoDirectory.java)
    @Override
    @SuppressWarnings("ConvertToTryWithResources")
    public synchronized void close() throws IOException {
        readAheadworker.close();
        encryptionMetadataCache.invalidateDirectory();

        // Invalidate all cache entries for this directory to prevent memory leaks
        // when the shard/index is closed or deleted.
        //
        // L1 RadixBlockTable entries for this directory's files are cleaned up via two
        // mechanisms:
        // 1. invalidateByPathPrefix below triggers Caffeine evictions, which fire the
        // eviction listener -> registry.onEviction() -> L1 slots nulled.
        // 2. Master IndexInput.close() calls registry.release(path) per file, which clears
        // and removes the table when refCount reaches 0.
        if (blockCache != null) {
            blockCache.invalidateByPathPrefix(dirPath);
        }

        // Also drop (and close) any cached read FileChannels under this directory, so a removed/closed
        // index does not leave FDs pinning unlinked inodes (bounded by the FD cache's LRU) that remain
        // available for a later path reuse -> stale-ciphertext read. Mirrors the block-cache prefix
        // invalidation above; same key normalization as the backend.
        CryptoDirectoryFactory.invalidateFileChannelsByPrefix(dirPath);
    }

    @Override
    public void deleteFile(String name) throws IOException {
        Path file = dirPath.resolve(name);

        // Cancel any pending async read-ahead operations for this file FIRST
        // to prevent race where read-ahead tries to load blocks from deleted/replaced file
        readAheadworker.cancel(file);

        // Invalidate the cached read FileChannel BEFORE the unlink as well as after (below). Without the
        // before-unlink invalidation there is a window: between super.deleteFile (unlink) and the post-unlink
        // CryptoDirectoryFactory.invalidateFileChannel, a concurrent reader on a still-open IndexInput can miss
        // the block cache, reopen a fresh FD to the unlinked-but-still-valid inode, and re-cache it. That FD
        // would then survive the post-unlink invalidate and serve OLD-inode bytes if the path is recreated.
        // rename already invalidates before and after the move; mirror that here. (Dropping the FD before the
        // unlink is safe: any in-flight read reopens on demand via FileChannelBackend.)
        CryptoDirectoryFactory.invalidateFileChannel(file);

        if (blockCache != null) {
            try {
                long fileSize = Files.size(file);
                if (fileSize > 0) {
                    final int totalBlocks = (int) ((fileSize + CACHE_BLOCK_SIZE - 1) >>> CACHE_BLOCK_SIZE_POWER);
                    for (int i = 0; i < totalBlocks; i++) {
                        final long blockOffset = (long) i << CACHE_BLOCK_SIZE_POWER;
                        FileBlockCacheKey key = new FileBlockCacheKey(file, blockOffset);
                        blockCache.invalidate(key);
                    }
                }
            } catch (IOException e) {
                // Fall back to path-based invalidation if file size unavailable. This is
                // load-bearing: the L1 RadixBlockTable has no generation/pin check and relies
                // on the L2 eviction listener firing, so any L2 entry left behind here is never
                // evicted -> L1 never cleared -> a later read of a reused path can be served
                // stale ciphertext decrypted under the wrong context. Invalidate by path so all
                // cached blocks for the file are dropped even when the block count is unknown.
                LOGGER.warn("Failed to get file size for clearing cache; falling back to path-based invalidation", e);
                blockCache.invalidate(file);
            }
        }
        super.deleteFile(name);
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(file));

        // Clear this file's L1 RadixBlockTable directly, so L1 coherence on a delete-then-recreate at the
        // same path does NOT depend on the L2 removal listener firing for every block. The block-cache
        // invalidation above drives onEviction for blocks still present in L2, but a reader can re-publish
        // an entry into L1 just after its per-block onEviction ran (the publishToL1 re-check narrows, but
        // cannot fully close, that window), and an entry whose L2 value was already gone never gets an
        // eviction callback at all. Emptying the whole file's table here removes that timing dependency.
        radixBlockTableRegistry.clearFile(file);

        // Drop (and close) any cached read FileChannel for this path. The node-global FD cache is
        // keyed by absolute path, so on a delete-then-recreate at the same path (recovery re-fetch,
        // snapshot restore, keyfile churn) a stale cached FD would otherwise keep serving the OLD
        // inode's ciphertext while the footer/file-key is re-read fresh from the NEW inode -> new key
        // applied to old ciphertext. Because the data read path is unauthenticated AES-CTR this would
        // not fail fast; it would surface later as a Lucene CRC / CorruptIndexException or undetected
        // stale data. Invalidate here (after the unlink) with the same key normalization the backend
        // uses, mirroring the block-cache + encryption-metadata invalidation above.
        CryptoDirectoryFactory.invalidateFileChannel(file);
    }

    /**
     * {@inheritDoc}
     *
     * <p>An atomic rename replaces {@code dest} (unlinking its previous inode) and removes
     * {@code source}. Both paths must therefore have their cached state dropped, for the same reason
     * {@link #deleteFile(String)} does: the node-global FD cache, the block cache, and the
     * encryption-metadata cache are all keyed by absolute path, so a stale entry for either path would
     * later serve OLD-inode ciphertext while the footer/file-key is re-resolved from the NEW inode —
     * silent garbage under the unauthenticated AES-CTR read path. We invalidate {@code dest} both
     * before and after the move: before, to drop any entry bound to the inode being replaced; after,
     * to drop anything a concurrent reader may have re-cached during the move. (This narrows but does
     * not fully close the concurrent-reader repopulation window — see CryptoDirectoryFactory.)
     */
    @Override
    public void rename(String source, String dest) throws IOException {
        Path sourceFile = dirPath.resolve(source);
        Path destFile = dirPath.resolve(dest);

        readAheadworker.cancel(sourceFile);
        readAheadworker.cancel(destFile);

        // Drop the destination's stale cached state (its inode is about to be replaced).
        if (blockCache != null) {
            blockCache.invalidate(destFile);
        }
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(destFile));
        CryptoDirectoryFactory.invalidateFileChannel(destFile);

        super.rename(source, dest);

        // After the move: source no longer exists; destination now maps to the moved inode. Drop any
        // cached state for both paths (incl. anything re-cached during the move) so subsequent reads
        // resolve the new inode's footer/key against the new inode's bytes.
        if (blockCache != null) {
            blockCache.invalidate(sourceFile);
            blockCache.invalidate(destFile);
        }
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(sourceFile));
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(destFile));
        CryptoDirectoryFactory.invalidateFileChannel(sourceFile);
        CryptoDirectoryFactory.invalidateFileChannel(destFile);

        // Clear both paths' L1 RadixBlockTables directly (see deleteFile): the dest inode was replaced and
        // the source removed, so any L1 entry for either path is now stale. Doing it here rather than
        // relying on the L2-eviction->onEviction ordering closes the publish-after-evict window the
        // reader-side publishToL1 re-check can only narrow.
        radixBlockTableRegistry.clearFile(sourceFile);
        radixBlockTableRegistry.clearFile(destFile);
    }

    /**
     * Calculate content length by reading footer if file is an OSEF file.
     * Returns raw file size for non-OSEF files (< MIN_FOOTER_SIZE).
     */
    private long calculateContentLengthWithValidation(Path file, long rawFileSize) throws IOException {
        if (rawFileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            return rawFileSize;
        }

        String normalizedPath = EncryptionMetadataCache.normalizePath(file);

        // Check cache first for fast path
        EncryptionFooter cachedFooter = encryptionMetadataCache.getFooter(normalizedPath);
        if (cachedFooter != null) {
            return rawFileSize - cachedFooter.getFooterLength();
        }

        // Cache miss - read footer from disk (happens during file open before cache populated)
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            EncryptionFooter footer = EncryptionFooter.readViaFileChannel(normalizedPath, channel, masterKeyBytes, encryptionMetadataCache);

            // Metadata is already cached by readViaFileChannel

            return rawFileSize - footer.getFooterLength();
        } catch (EncryptionFooter.NotOSEFFileException e) {
            // Not an encrypted file - return raw size
            return rawFileSize;
        }
    }

    private void logCacheAndPoolStats() {
        try {

            if (blockCache instanceof CaffeineBlockCache) {
                String cacheStats = ((CaffeineBlockCache<?, ?>) blockCache).cacheStats();
                LOGGER.info("{}", cacheStats);
            }

            // Pool stats — direct-memory usage, OS-free tracking, throttle-engaged history — the
            // signals we need to correlate with recovery-time Track 6 WARNs (see delete_optimisation
            // journal §32-34). Runs on the background telemetry thread, never on the hot path.
            if (memorySegmentPool instanceof org.opensearch.index.store.pool.MemorySegmentPool msp) {
                LOGGER.info("Pool[{}]", msp.poolStats());
            }

            // L1 (RadixBlockTable) stats — hit rate is the leading indicator of cold-segment
            // decrypt latency. Emitted alongside Cache[ and Pool[ for one-line telemetry view.
            if (radixBlockTableRegistry != null) {
                LOGGER.info("{}", radixBlockTableRegistry.l1Stats());
            }

        } catch (Exception e) {
            LOGGER.warn("Failed to log cache/pool stats", e);
        }
    }

    // Background 10s cadence dumper for cache + pool telemetry. Off the hot path — daemon thread only.
    private void startCacheStatsTelemetry() {
        Thread loggerThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(Duration.ofSeconds(10));
                    logCacheAndPoolStats();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Throwable t) {
                    LOGGER.warn("Error in collecting cache stats", t);
                }
            }
        });

        loggerThread.setDaemon(true);
        loggerThread.setName("DirectIOBufferPoolStatsLogger");
        loggerThread.start();
    }
}
