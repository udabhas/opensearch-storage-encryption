/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_MASK;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.cipher.MemorySegmentDecryptor;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;
import org.opensearch.index.store.pool.Pool;

/**
 * A {@link BlockLoader} implementation that loads encrypted file blocks using Direct I/O
 * and automatically decrypts them in-place.
 *
 * <p>This loader combines high-performance Direct I/O with transparent decryption to provide
 * efficient access to encrypted file data. It reads blocks directly from storage, bypassing
 * the OS buffer cache, then decrypts the data in memory using the configured key and IV resolver.
 *
 * <p>Key features:
 * <ul>
 * <li>Direct I/O for high performance and reduced memory pressure</li>
 * <li>Automatic in-place decryption of loaded blocks</li>
 * <li>Memory pool integration for efficient buffer management</li>
 * <li>Block-aligned operations for optimal storage performance</li>
 * </ul>
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
public class CryptoDirectIOBlockLoader implements BlockLoader<RefCountedByteBuffer> {
    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectIOBlockLoader.class);

    private final KeyResolver keyResolver;
    private final Pool<RefCountedByteBuffer> segmentPool;
    private final EncryptionMetadataCache encryptionMetadataCache;

    /** Direct-I/O backend with the node-level cached FileChannel (avoids open()/close() per block load). */
    private static final FileChannelBackend IO_BACKEND = new FileChannelBackend();

    /**
     * Bounded retry for a zero-byte Direct-I/O read. A valid, non-empty file can transiently return
     * 0 bytes on a network filesystem (NFS/EFS client data-cache staleness right after a metadata change);
     * a single attempt would surface that as a spurious EOFException and fail (RED) the shard. Local
     * EBS/NVMe does not exhibit this, so in practice the first attempt succeeds and the retry
     * loop is never entered — it is cheap insurance for denser / shared-storage configurations.
     */
    private static final int ZERO_BYTE_READ_MAX_ATTEMPTS = 3;
    private static final long ZERO_BYTE_READ_INITIAL_DELAY_MS = 5L;

    /** Rate-limit window for the degraded-read WARN so a sustained pool-exhaustion incident does not flood the log. */
    private static final long DEGRADED_WARN_INTERVAL_MS = 60_000L;
    /** Last-WARN timestamp (epoch ms) used as a CAS gate so only one thread WARNs per window. */
    private static final java.util.concurrent.atomic.AtomicLong DEGRADED_WARN_GATE = new java.util.concurrent.atomic.AtomicLong(0L);

    /**
     * Constructs a new CryptoDirectIOBlockLoader with the specified memory pool and key resolver.
     *
     * @param segmentPool the memory segment pool for acquiring buffer space
     * @param keyResolver the resolver for obtaining encryption keys and initialization vectors
     * @param encryptionMetadataCache the per-file encryption metadata (footer + derived key) cache
     */
    public CryptoDirectIOBlockLoader(
        Pool<RefCountedByteBuffer> segmentPool,
        KeyResolver keyResolver,
        EncryptionMetadataCache encryptionMetadataCache
    ) {
        this.segmentPool = segmentPool;
        this.keyResolver = keyResolver;
        this.encryptionMetadataCache = encryptionMetadataCache;
    }

    @Override
    public RefCountedByteBuffer[] load(Path filePath, long startOffset, long blockCount, long poolTimeoutMs) throws Exception {
        // fdc-debug: the ONLY line that proves real block IO happened. Emitted per load, so it is the
        // volume driver of a trace run - on the order of 18k lines per GiB of blocks read. The caller
        // chain is walked only under -Dopensearch.store.fdcdebug.hotstacks=true.
        if (FdcDebug.on(LOGGER)) {
            int callsite = FdcDebug.hotSite(LOGGER, "loader.load", filePath);
            FdcDebug
                .log(
                    LOGGER,
                    "fdc-debug loader thread={} file={} offset={} blocks={} readBytes={} blockSize={} callsite={}",
                    FdcDebug.thread(),
                    filePath,
                    startOffset,
                    blockCount,
                    (blockCount << CACHE_BLOCK_SIZE_POWER),
                    CACHE_BLOCK_SIZE,
                    callsite
                );
        }
        if (!Files.exists(filePath)) {
            throw new NoSuchFileException(filePath.toString());
        }

        if ((startOffset & CACHE_BLOCK_MASK) != 0) {
            throw new IllegalArgumentException("startOffset must be block-aligned: " + startOffset);
        }

        if (blockCount <= 0) {
            throw new IllegalArgumentException("blockCount must be positive: " + blockCount);
        }

        RefCountedByteBuffer[] result = new RefCountedByteBuffer[(int) blockCount];
        long readLength = blockCount << CACHE_BLOCK_SIZE_POWER;

        // Filesystem block size for Direct I/O alignment (local disk).
        int fsBlockSize = Math.toIntExact(Files.getFileStore(filePath).getBlockSize());

        try (Arena arena = Arena.ofConfined()) {
            // Query-profiler handle (null unless a ?profile=true query is scoring on this thread).
            final org.opensearch.index.store.profile.CryptoQueryProfile prof = org.opensearch.index.store.profile.CryptoQueryProfile
                .current();
            // Total-load latency: the WHOLE plugin load() operation (IO + footer/HKDF + decrypt + pool
            // acquire + buffer copy + loop). Recorded into the crypto_load_time_dist histogram in the
            // finally, so it covers return/throw/degraded.
            final long loadStartNs = (prof != null) ? System.nanoTime() : 0L;
            try {
                // Read via the shared FileChannel backend (node-level cached, positional Direct I/O reads).
                // Reusing the open channel across block-cache misses avoids an open()/close() syscall per load.
                // Per-read disk-IO latency for the crypto_io_time_dist histogram.
                final long ioStartNs = (prof != null) ? System.nanoTime() : 0L;
                MemorySegment readBytes = readWithZeroByteRetry(filePath, startOffset, readLength, arena, fsBlockSize);
                long bytesRead = readBytes.byteSize();

                // Reject an empty read before recording read metrics, so a zero-size sample is not folded
                // into crypto_read_size_bytes / crypto_bytes_read for a load that is about to throw.
                if (bytesRead == 0) {
                    throw new java.io.EOFException("Unexpected EOF or empty read at offset " + startOffset + " for file " + filePath);
                }

                if (prof != null) {
                    prof.recordIoLatency(System.nanoTime() - ioStartNs);
                    prof.recordReadSize(bytesRead);
                    prof.addBytesRead(bytesRead);
                }

                String normalizedPath = filePath.toAbsolutePath().normalize().toString();
                byte[] masterKey = keyResolver.getDataKey().getEncoded();

                // Get footer from disk (readFooterFromDisk populates the metadata cache with an inode-stamped
                // entry when the inode is stable — see EncryptionFooter.readViaFileChannel). Derive messageId/key
                // straight from THIS footer rather than re-fetching via the path-based getOrLoadMetadata: a
                // re-fetch would re-stat the name and could bind this read's footer to a concurrently-recreated
                // inode (TOCTOU). The footer here is authoritative for the bytes we just read.
                final org.opensearch.index.store.profile.CryptoNanosMetric footerTimer = (prof != null) ? prof.footerHkdfTimer() : null;
                final long footerStartNs = (footerTimer != null) ? footerTimer.start() : 0L;
                EncryptionFooter footer;
                byte[] messageId;
                byte[] fileKey;
                try {
                    footer = readFooterFromDisk(filePath, masterKey);
                    messageId = footer.getMessageId();
                    fileKey = org.opensearch.index.store.key.HkdfKeyDerivation.deriveFileKey(masterKey, messageId);
                } finally {
                    if (footerTimer != null)
                        footerTimer.stop(footerStartNs);
                }

                // Use frame-based decryption with derived file key.
                // Per-block decrypt latency for the crypto_decrypt_time_dist histogram (no-op when not
                // profiling — current() returns null).
                final long decryptStartNs = (prof != null) ? System.nanoTime() : 0L;
                try {
                    MemorySegmentDecryptor
                        .decryptInPlaceFrameBased(
                            readBytes.address(),
                            readBytes.byteSize(),
                            fileKey,                                    // Derived file key (matches write path)
                            masterKey,                                  // Master key for IV computation
                            messageId,                                  // Message ID from footer
                            org.opensearch.index.store.footer.EncryptionMetadataTrailer.DEFAULT_FRAME_SIZE, // Frame size
                            startOffset,                                 // File offset
                            filePath.toAbsolutePath().normalize().toString(),
                            encryptionMetadataCache
                        );
                } finally {
                    if (prof != null) {
                        prof.recordDecryptLatency(System.nanoTime() - decryptStartNs);
                    }
                }

                int blockIndex = 0;
                long bytesCopied = 0;

                try {
                    while (blockIndex < blockCount && bytesCopied < bytesRead) {
                        int remaining = (int) (bytesRead - bytesCopied);
                        int toCopy = Math.min(CACHE_BLOCK_SIZE, remaining);

                        // Acquire a pooled buffer (5s for critical loads, 50ms for prefetch). If the pool
                        // is exhausted/throttled and the timeout elapses, DEGRADE rather than fail the read:
                        // back this block with a transient, non-pooled, non-cacheable buffer so the read
                        // completes uncached instead of turning a memory-pressure throttle into a fatal
                        // RecoveryFailedException (shard RED). The decrypted bytes are already in
                        // {@code readBytes}; only the cache-warm of this block is sacrificed.
                        //
                        // The fallback MUST use a HEAP buffer (ByteBuffer.allocate), NOT allocateDirect: the
                        // throttle/exhaustion we are recovering from means the -XX:MaxDirectMemorySize budget
                        // is the scarce resource, so allocating MORE direct memory here would (a) add to the
                        // pressure and (b) risk an OutOfMemoryError — an Error, not an IOException, which would
                        // escape every catch on this path and propagate fatally through Caffeine to recovery,
                        // re-creating the exact RED this fallback exists to prevent. Heap allocation draws from
                        // the GC heap and cannot raise the direct-memory OOM. (This differs from the write path,
                        // which on pool-acquire failure allocates nothing and simply skips the cache-warm.)
                        RefCountedByteBuffer handle;
                        final org.opensearch.index.store.profile.CryptoNanosMetric poolWaitTimer = (prof != null)
                            ? prof.poolWaitTimer()
                            : null;
                        final long poolStartNs = (poolWaitTimer != null) ? poolWaitTimer.start() : 0L;
                        try {
                            handle = segmentPool.tryAcquire(poolTimeoutMs, TimeUnit.MILLISECONDS);
                            if (poolWaitTimer != null)
                                poolWaitTimer.stop(poolStartNs);
                        } catch (InterruptedException e) {
                            if (poolWaitTimer != null)
                                poolWaitTimer.stop(poolStartNs);
                            releaseHandles(result, blockIndex);
                            Thread.currentThread().interrupt();
                            throw new IOException("Interrupted while acquiring pool segment", e);
                        } catch (IOException | OutOfMemoryError e) {
                            // Degraded fallback: serve the block from a transient HEAP buffer that is NOT
                            // pool-accounted and MUST NOT be cached (see RefCountedByteBuffer.transientFallback).
                            // We also catch OutOfMemoryError defensively: if the pool's own allocateDirect
                            // exhausted direct memory and rethrew the OOM, we degrade here rather than let the
                            // Error fail the shard.
                            // Count every degraded read (always — cheap) and WARN on the first occurrence in
                            // each rate-limit window. DEBUG alone (off in prod) made a node silently serving
                            // uncached reads under memory pressure look identical to a healthy one, hiding the
                            // exact saturation signal needed during an incident.
                            // Bare call — the metrics singleton is initialized at node startup.
                            if (poolWaitTimer != null)
                                poolWaitTimer.stop(poolStartNs);
                            if (prof != null)
                                prof.incDegradedReads();
                            CryptoMetricsService.getInstance().recordDegradedRead();
                            long nowMs = System.currentTimeMillis();
                            long lastWarn = DEGRADED_WARN_GATE.get();
                            if (nowMs - lastWarn >= DEGRADED_WARN_INTERVAL_MS && DEGRADED_WARN_GATE.compareAndSet(lastWarn, nowMs)) {
                                LOGGER
                                    .warn(
                                        "Pool exhausted/throttled — serving DEGRADED (uncached, heap-fallback) read for path={} "
                                            + "offset={} block={}: {}. Node is shedding cache under memory pressure "
                                            + "(see crypto.read.degraded.total).",
                                        filePath,
                                        startOffset,
                                        blockIndex,
                                        e.toString()
                                    );
                            } else {
                                LOGGER
                                    .debug(
                                        "Pool acquire failed (degraded, uncached, heap fallback) for path={} offset={} block={}: {}",
                                        filePath,
                                        startOffset,
                                        blockIndex,
                                        e.toString()
                                    );
                            }
                            handle = RefCountedByteBuffer
                                .transientFallback(
                                    java.nio.ByteBuffer.allocate(CACHE_BLOCK_SIZE).order(java.nio.ByteOrder.LITTLE_ENDIAN),
                                    CACHE_BLOCK_SIZE
                                );
                        }

                        if (toCopy > 0) {
                            MemorySegment.copy(readBytes, bytesCopied, handle.segment(), 0, toCopy);
                        }

                        result[blockIndex++] = handle;  // Store the handle, not the segment
                        if (prof != null)
                            prof.incBlocksDecrypted();
                        bytesCopied += toCopy;
                    }
                } catch (IOException e) {
                    // Only reached for the genuinely-fatal interrupt path above; pool exhaustion no longer
                    // reaches here (it degrades). Release any handles acquired so far, then propagate.
                    releaseHandles(result, blockIndex);
                    throw e;
                }

                return result;

            } finally {
                if (prof != null)
                    prof.recordLoadLatency(System.nanoTime() - loadStartNs);
            }

        } catch (NoSuchFileException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("Bulk read failed: path={} offset={} length={} err={}", filePath, startOffset, readLength, e.toString());
            throw e;
        }
    }

    /**
     * Read via the cached FileChannel Direct-I/O backend, retrying a SHORT read (zero-byte OR
     * partial-then-stalled) up to {@link #ZERO_BYTE_READ_MAX_ATTEMPTS} times with a short linear
     * backoff, and failing loudly if the full expected length is still not read.
     *
     * <p>Correctness contract: a non-EOF read must return exactly the expected number of bytes, where
     * {@code expected = min(readLength, fileSize - startOffset)}. The previous guard accepted ANY
     * non-empty read ({@code byteSize() > 0}) as complete, so a partial-then-transient-zero read (some
     * bytes, then a 0-byte return before the full request was satisfied) was accepted and the block's
     * unread tail was decrypted/served as uninitialized or stale bytes. Because the data read path is
     * unauthenticated AES-CTR, that does not fail fast — it surfaces later as a Lucene CRC /
     * {@code CorruptIndexException}. Verifying the full expected length covers both the all-zero and the
     * partial-then-zero cases, and never returns an under-filled non-final block. See
     * {@link #ZERO_BYTE_READ_MAX_ATTEMPTS} for why transient short reads can occur on network filesystems
     * (latent on local EBS/NVMe, but cheap insurance for denser/shared-storage configs).
     */
    private MemorySegment readWithZeroByteRetry(Path filePath, long startOffset, long readLength, Arena arena, int fsBlockSize)
        throws IOException {
        // Bytes the file can actually supply for this range; a read shorter than this (when not at true
        // EOF) is a transient short read to be retried, NOT a legitimate end-of-file short read.
        long fileSize = Files.size(filePath);
        long expected = Math.max(0L, Math.min(readLength, fileSize - startOffset));

        MemorySegment readBytes = IO_BACKEND.read(filePath, startOffset, readLength, arena, fsBlockSize);
        if (readLength == 0 || readBytes.byteSize() >= expected) {
            return readBytes;  // got everything the file can give for this range (incl. legit EOF short read)
        }
        for (int attempt = 1; attempt < ZERO_BYTE_READ_MAX_ATTEMPTS; attempt++) {
            // Meter the retry via the existing error flow (crypto.error.total{error_type=read_short_read_retry}):
            // a sub-full read on a network filesystem (NFS/EFS cache staleness) is a silent-corruption precursor
            // under unauthenticated AES-CTR. Bare call — the metrics
            // singleton is initialized at node startup.
            CryptoMetricsService.getInstance().recordError(ErrorType.READ_SHORT_READ_RETRY);
            LOGGER
                .warn(
                    "Short read at offset {} for {} (got {} of expected {} bytes; possible fs cache staleness or "
                        + "partial Direct-I/O read), retrying ({}/{})",
                    startOffset,
                    filePath,
                    readBytes.byteSize(),
                    expected,
                    attempt,
                    ZERO_BYTE_READ_MAX_ATTEMPTS - 1
                );
            try {
                Thread.sleep(ZERO_BYTE_READ_INITIAL_DELAY_MS * attempt);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during short-read retry for " + filePath, ie);
            }
            readBytes = IO_BACKEND.read(filePath, startOffset, readLength, arena, fsBlockSize);
            if (readBytes.byteSize() >= expected) {
                return readBytes;
            }
        }
        // Still short after retries: fail loudly rather than decrypt/serve an under-filled block as
        // valid plaintext (silent corruption under AES-CTR). The block cache load propagates this.
        throw new IOException(
            "Short read after "
                + (ZERO_BYTE_READ_MAX_ATTEMPTS - 1)
                + " retries: got "
                + readBytes.byteSize()
                + " of expected "
                + expected
                + " bytes at offset "
                + startOffset
                + " for "
                + filePath
        );
    }

    private void releaseHandles(RefCountedByteBuffer[] handles, int upTo) {
        // close() is a no-op on the GC-managed RefCountedByteBuffer; dropping the references
        // here lets the JVM Cleaner reclaim the backing direct buffers (and decrement the
        // pool's buffersInUse counter) once they become unreachable. Retained for clarity
        // of partial-failure cleanup intent.
        for (int i = 0; i < upTo; i++) {
            if (handles[i] != null) {
                handles[i].close();
                handles[i] = null;
            }
        }
    }

    private EncryptionFooter readFooterFromDisk(Path filePath, byte[] masterKey) throws IOException {
        String normalizedPath = filePath.toAbsolutePath().normalize().toString();

        // Check cache first for fast path
        EncryptionFooter cachedFooter = encryptionMetadataCache.getFooter(normalizedPath);
        if (cachedFooter != null) {
            return cachedFooter;
        }

        // Cache miss - read from disk
        try (FileChannel channel = FileChannel.open(filePath, StandardOpenOption.READ)) {
            long fileSize = channel.size();
            if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
                throw new IOException("File too small to contain footer: " + filePath);
            }

            // Read minimum footer to check OSEF magic bytes
            ByteBuffer minBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            channel.read(minBuffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            byte[] minFooterBytes = minBuffer.array();

            // Check if this is an OSEF file
            if (!isValidOSEFFile(minFooterBytes)) {
                // Not an OSEF file
                throw new IOException("Not an OSEF file -" + filePath);
            }

            return EncryptionFooter.readViaFileChannel(normalizedPath, channel, masterKey, encryptionMetadataCache);
        }
    }

    /**
     * Check if file has valid OSEF magic bytes
     */
    private boolean isValidOSEFFile(byte[] minFooterBytes) {
        int magicOffset = minFooterBytes.length - EncryptionMetadataTrailer.MAGIC.length;
        for (int i = 0; i < EncryptionMetadataTrailer.MAGIC.length; i++) {
            if (minFooterBytes[magicOffset + i] != EncryptionMetadataTrailer.MAGIC[i]) {
                return false;
            }
        }
        return true;
    }
}
