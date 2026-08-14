/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.Directory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.apache.lucene.tests.mockfile.ExtrasFS;
import org.opensearch.common.Randomness;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCacheKey;
import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_loader.CryptoDirectIOBlockLoader;
import org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTableRegistry;
import org.opensearch.index.store.bufferpoolfs.StaticConfigs;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.hybrid.HybridCryptoDirectory;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.index.store.pool.MemorySegmentPool;
import org.opensearch.index.store.read_ahead.Worker;
import org.opensearch.index.store.read_ahead.impl.QueuingWorker;
import org.opensearch.telemetry.metrics.MetricsRegistry;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Shared factory for constructing crypto directory instances in tests.
 * Provides real (not mocked) encryption infrastructure with random keys.
 *
 * <p>Directories returned by this factory clean up their thread pools and
 * native memory pools on {@link java.io.Closeable#close()}.
 */
public final class CryptoTestDirectoryFactory {

    /** Name of the encryption key file created by {@code DefaultKeyResolver}. */
    public static final String KEY_FILE_NAME = "keyfile";

    private static final Provider PROVIDER = Security.getProvider("SunJCE");
    private static final AtomicBoolean METRICS_INITIALIZED = new AtomicBoolean(false);

    /**
     * NIO extensions matching OpenSearch's production default
     * ({@code IndexModule.INDEX_STORE_HYBRID_NIO_EXTENSIONS}).
     */
    private static final Set<String> NIO_EXTENSIONS = Set
        .of("si", "cfe", "fnm", "fdx", "fdt", "pos", "pay", "nvm", "dvm", "tvx", "tvd", "liv", "dii", "vem");

    private CryptoTestDirectoryFactory() {}

    /** Ensures CryptoMetricsService is initialized for tests. Safe to call multiple times. */
    public static void initMetrics() {
        if (METRICS_INITIALIZED.compareAndSet(false, true)) {
            CryptoMetricsService.initialize(mock(MetricsRegistry.class));
        }
    }

    /** Creates a random 256-bit AES KeyResolver using the test's random source. */
    public static KeyResolver createKeyResolver() {
        byte[] rawKey = new byte[32];
        Randomness.get().nextBytes(rawKey);
        KeyResolver resolver = mock(KeyResolver.class);
        when(resolver.getDataKey()).thenReturn(new SecretKeySpec(rawKey, "AES"));
        return resolver;
    }

    /**
     * Shared implementation of {@code testCreateTempOutput} for crypto directories.
     * Crypto directories list an extra "keyfile" that the base test doesn't expect,
     * so this override filters it out before asserting.
     *
     * @param dir       the directory under test (caller is responsible for closing)
     * @param iters     number of temp files to create
     * @param random    the test's {@link java.util.Random} instance
     * @param ioCtxSupplier supplier for IOContext (typically {@code () -> newIOContext(random())})
     */
    public static void assertTempOutputRoundTrip(Directory dir, int iters, java.util.function.Supplier<IOContext> ioCtxSupplier)
        throws IOException {
        List<String> names = new ArrayList<>();
        for (int iter = 0; iter < iters; iter++) {
            IndexOutput out = dir.createTempOutput("foo", "bar", ioCtxSupplier.get());
            names.add(out.getName());
            out.writeVInt(iter);
            out.close();
        }
        for (int iter = 0; iter < iters; iter++) {
            IndexInput in = dir.openInput(names.get(iter), ioCtxSupplier.get());
            assertEquals(iter, in.readVInt());
            in.close();
        }

        Set<String> files = Arrays
            .stream(dir.listAll())
            .filter(file -> !ExtrasFS.isExtra(file))
            .filter(file -> !file.equals(KEY_FILE_NAME))
            .collect(Collectors.toSet());

        assertEquals(new HashSet<>(names), files);
    }

    public static CryptoNIOFSDirectory createCryptoNIOFSDirectory(Path path, LockFactory lockFactory) throws IOException {
        initMetrics();
        return new CryptoNIOFSDirectory(lockFactory, path, PROVIDER, createKeyResolver(), new EncryptionMetadataCache());
    }

    public static BufferPoolDirectory createBufferPoolDirectory(Path path, LockFactory lockFactory) throws IOException {
        initMetrics();
        KeyResolver keyResolver = createKeyResolver();
        EncryptionMetadataCache metadataCache = new EncryptionMetadataCache();
        return buildBufferPoolDirectory(path, lockFactory, keyResolver, metadataCache);
    }

    /**
     * Creates a HybridCryptoDirectory with production-matching NIO extension routing.
     * Files with extensions in {@link #NIO_EXTENSIONS} route to NIO; others to BufferPool.
     * Note: extensionless file names always route to NIO (production behavior).
     */
    public static HybridCryptoDirectory createHybridCryptoDirectory(Path path, LockFactory lockFactory) throws IOException {
        initMetrics();
        KeyResolver keyResolver = createKeyResolver();
        EncryptionMetadataCache metadataCache = new EncryptionMetadataCache();
        BufferPoolDirectory bufferPoolDir = buildBufferPoolDirectory(path, lockFactory, keyResolver, metadataCache);
        return new HybridCryptoDirectory(lockFactory, bufferPoolDir, PROVIDER, keyResolver, metadataCache, NIO_EXTENSIONS);
    }

    /**
     * Creates a HybridCryptoDirectory that routes ALL files through BufferPool,
     * including extensionless files. Use this for Lucene contract tests which
     * create files without extensions (e.g., "foobar", "byte", "int") that would
     * otherwise always route to NIO due to {@code delegeteBufferPool("")} returning false.
     *
     * <p>The NIO path is already covered by {@code CryptoDirectoryTests} which directly
     * tests {@code CryptoNIOFSDirectory}. This method ensures the BufferPool encryption
     * path gets exercised through the HybridCryptoDirectory layer.
     */
    public static HybridCryptoDirectory createBufferPoolRoutedHybridDirectory(Path path, LockFactory lockFactory) throws IOException {
        initMetrics();
        KeyResolver keyResolver = createKeyResolver();
        EncryptionMetadataCache metadataCache = new EncryptionMetadataCache();
        BufferPoolDirectory bufferPoolDir = buildBufferPoolDirectory(path, lockFactory, keyResolver, metadataCache);
        return new BufferPoolRoutedHybridDirectory(lockFactory, bufferPoolDir, PROVIDER, keyResolver, metadataCache, NIO_EXTENSIONS);
    }

    /**
     * Builds a BufferPoolDirectory with full encryption infrastructure.
     * The returned directory shuts down its executor and closes the native memory pool on close().
     */
    private static BufferPoolDirectory buildBufferPoolDirectory(
        Path path,
        LockFactory lockFactory,
        KeyResolver keyResolver,
        EncryptionMetadataCache metadataCache
    ) throws IOException {
        // Segment size MUST equal the production block size (StaticConfigs.CACHE_BLOCK_SIZE, derived
        // from CACHE_BLOCK_SIZE_POWER) — the block loader loads a full CACHE_BLOCK_SIZE block into a
        // single pooled segment, so a smaller segment overflows. Provision enough segments for the
        // Lucene contract's concurrent multi-block reads.
        final int segmentSize = StaticConfigs.CACHE_BLOCK_SIZE;
        // The block cache pins one pooled segment per cached block, so the pool must comfortably
        // exceed the cache's block count or reads fall back to the DEGRADED heap path (slow, with
        // multi-second pool-acquisition stalls). Keep pool >> cache: cache 256 blocks, pool 512.
        final long maxCachedBlocks = 256;
        final long totalMemory = 512L * segmentSize;
        MemorySegmentPool pool = new MemorySegmentPool(totalMemory, segmentSize);
        CryptoDirectIOBlockLoader blockLoader = new CryptoDirectIOBlockLoader(pool, keyResolver, metadataCache);

        Cache<BlockCacheKey, BlockCacheValue<RefCountedByteBuffer>> caffeineCache = Caffeine
            .newBuilder()
            .maximumSize(maxCachedBlocks)
            .expireAfterAccess(Duration.ofMinutes(5))
            .recordStats()
            .build();

        CaffeineBlockCache<RefCountedByteBuffer, RefCountedByteBuffer> blockCache = new CaffeineBlockCache<>(
            caffeineCache,
            blockLoader,
            maxCachedBlocks
        );

        ExecutorService executor = Executors.newFixedThreadPool(4);
        Worker worker = new QueuingWorker(100, executor);

        // Anonymous subclass that cleans up executor and native pool on close
        return new BufferPoolDirectory(
            path,
            lockFactory,
            PROVIDER,
            keyResolver,
            pool,
            blockCache,
            blockLoader,
            worker,
            metadataCache,
            new RadixBlockTableRegistry()
        ) {
            @Override
            public synchronized void close() throws IOException {
                super.close();
                executor.shutdownNow();
                pool.close();
            }
        };
    }

    /**
     * A pair of {@link HybridCryptoDirectory} instances over the SAME on-disk path that SHARE one
     * node-global block cache, memory pool, key resolver, and metadata cache. Models production, where the
     * block/FD caches are node-global and each shard incarnation gets a fresh directory over a reused path.
     * Close the pair (not the individual directories) to release the shared native pool.
     */
    public static final class SharedCacheHybridPair implements java.io.Closeable {
        /** First incarnation — call {@link Directory#close()} on it to simulate the shard leaving the node. */
        public final HybridCryptoDirectory first;
        /** Second incarnation over the same path — models the shard returning / a new directory. */
        public final HybridCryptoDirectory second;
        private final MemorySegmentPool pool;
        private final ExecutorService executorA;
        private final ExecutorService executorB;

        private SharedCacheHybridPair(
            HybridCryptoDirectory first,
            HybridCryptoDirectory second,
            MemorySegmentPool pool,
            ExecutorService executorA,
            ExecutorService executorB
        ) {
            this.first = first;
            this.second = second;
            this.pool = pool;
            this.executorA = executorA;
            this.executorB = executorB;
        }

        @Override
        public void close() throws IOException {
            try {
                second.close();
            } finally {
                executorA.shutdownNow();
                executorB.shutdownNow();
                pool.close();
            }
        }
    }

    /**
     * Builds two {@link HybridCryptoDirectory} instances over {@code path} that SHARE one block cache, memory
     * pool, key resolver, and metadata cache — the production shape (node-global caches, per-incarnation
     * directory). The FIRST directory's {@code close()} runs the real {@code BufferPoolDirectory} prefix
     * invalidation (block + FD caches) but does NOT close the shared pool, so the second directory stays usable.
     * Used to prove that {@code close()}'s cache invalidation is what keeps a path reuse coherent.
     */
    public static SharedCacheHybridPair createSharedCacheHybridPair(Path path, LockFactory lockFactory) throws IOException {
        initMetrics();
        KeyResolver keyResolver = createKeyResolver();
        EncryptionMetadataCache metadataCache = new EncryptionMetadataCache();

        final int segmentSize = StaticConfigs.CACHE_BLOCK_SIZE;
        final long maxCachedBlocks = 256;
        final long totalMemory = 512L * segmentSize;
        MemorySegmentPool pool = new MemorySegmentPool(totalMemory, segmentSize);
        CryptoDirectIOBlockLoader blockLoader = new CryptoDirectIOBlockLoader(pool, keyResolver, metadataCache);

        Cache<BlockCacheKey, BlockCacheValue<RefCountedByteBuffer>> caffeineCache = Caffeine
            .newBuilder()
            .maximumSize(maxCachedBlocks)
            .expireAfterAccess(Duration.ofMinutes(5))
            .recordStats()
            .build();
        CaffeineBlockCache<RefCountedByteBuffer, RefCountedByteBuffer> blockCache = new CaffeineBlockCache<>(
            caffeineCache,
            blockLoader,
            maxCachedBlocks
        );

        // Shared L1 registry over the shared L2 cache (node-global in prod).
        RadixBlockTableRegistry radixRegistry = new RadixBlockTableRegistry();

        // Each directory gets its OWN read-ahead worker so closing the first does not close the second's worker;
        // everything else (pool, block cache, loader, metadata cache, key resolver, L1 registry) is shared.
        ExecutorService executorA = Executors.newFixedThreadPool(2);
        ExecutorService executorB = Executors.newFixedThreadPool(2);
        Worker workerA = new QueuingWorker(100, executorA);
        Worker workerB = new QueuingWorker(100, executorB);

        BufferPoolDirectory bpA = new BufferPoolDirectory(
            path,
            lockFactory,
            PROVIDER,
            keyResolver,
            pool,
            blockCache,
            blockLoader,
            workerA,
            metadataCache,
            radixRegistry
        );
        BufferPoolDirectory bpB = new BufferPoolDirectory(
            path,
            lockFactory,
            PROVIDER,
            keyResolver,
            pool,
            blockCache,
            blockLoader,
            workerB,
            metadataCache,
            radixRegistry
        );

        HybridCryptoDirectory first = new HybridCryptoDirectory(lockFactory, bpA, PROVIDER, keyResolver, metadataCache, NIO_EXTENSIONS);
        HybridCryptoDirectory second = new HybridCryptoDirectory(lockFactory, bpB, PROVIDER, keyResolver, metadataCache, NIO_EXTENSIONS);
        return new SharedCacheHybridPair(first, second, pool, executorA, executorB);
    }

    /**
     * Test-only HybridCryptoDirectory that routes ALL files through BufferPool,
     * overriding the extension-based routing logic. This ensures Lucene contract tests
     * exercise the encrypted BufferPool I/O path rather than the NIO pass-through.
     */
    static class BufferPoolRoutedHybridDirectory extends HybridCryptoDirectory {
        private final BufferPoolDirectory bpDir;

        BufferPoolRoutedHybridDirectory(
            LockFactory lockFactory,
            BufferPoolDirectory delegate,
            Provider provider,
            KeyResolver keyResolver,
            EncryptionMetadataCache cache,
            Set<String> nioExtensions
        )
            throws IOException {
            super(lockFactory, delegate, provider, keyResolver, cache, nioExtensions);
            this.bpDir = delegate;
        }

        @Override
        public IndexInput openInput(String name, IOContext context) throws IOException {
            ensureOpen();
            ensureCanRead(name);
            return bpDir.openInput(name, context);
        }

        @Override
        public IndexOutput createOutput(String name, IOContext context) throws IOException {
            ensureOpen();
            return bpDir.createOutput(name, context);
        }

        @Override
        public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
            return bpDir.createTempOutput(prefix, suffix, context);
        }

        // Intentionally NOT overriding deleteFile: production HybridCryptoDirectory routes all deletes
        // through NIOFS/FSDirectory (super), which provides pending-deletion tracking. Delegating to
        // the buffer pool here would diverge from production and break the pending-deletion contract.
    }
}
