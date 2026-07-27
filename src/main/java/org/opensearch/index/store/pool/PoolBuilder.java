/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;

import java.io.Closeable;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinWorkerThread;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheBuilder;
import org.opensearch.index.store.block_cache.PrefetchTracker;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTableRegistry;
import org.opensearch.index.store.read_ahead.Worker;
import org.opensearch.index.store.read_ahead.impl.NoopWorker;
import org.opensearch.index.store.read_ahead.impl.ReadAheadSizingPolicy;

/**
 * Builder for creating shared pool and cache resources with proper lifecycle management.
 * This class handles initialization of node-level shared resources used across all
 * encrypted directories.
 */
public final class PoolBuilder {

    private static final Logger LOGGER = LogManager.getLogger(PoolBuilder.class);

    /** 
    * Initial size for cache data structures (64K entries).
    */
    public static final int CACHE_INITIAL_SIZE = 65536;

    private PoolBuilder() {}

    /**
     * Container for shared pool resources with lifecycle management.
     * This class holds references to the shared memory segment pool, block cache,
     * telemetry thread, cache removal executor, and read-ahead executor service,
     * providing proper cleanup when closed.
     */
    public static class PoolResources implements Closeable {
        private final Pool<RefCountedByteBuffer> segmentPool;
        private final BlockCache<RefCountedByteBuffer> blockCache;
        private final long maxCacheBlocks;
        private final int readAheadQueueSize;
        private final Worker sharedReadaheadWorker;
        private final TelemetryThread telemetry;
        private final java.util.concurrent.ThreadPoolExecutor removalExecutor;
        private final ExecutorService readAheadExecutor;
        private final RadixBlockTableRegistry radixBlockTableRegistry;
        private final PrefetchTracker prefetchTracker;
        private final ExecutorService prefetchExecutor;

        PoolResources(
            Pool<RefCountedByteBuffer> segmentPool,
            BlockCache<RefCountedByteBuffer> blockCache,
            long maxCacheBlocks,
            int readAheadQueueSize,
            Worker sharedReadaheadWorker,
            TelemetryThread telemetry,
            java.util.concurrent.ThreadPoolExecutor removalExecutor,
            ExecutorService readAheadExecutor,
            RadixBlockTableRegistry radixBlockTableRegistry,
            PrefetchTracker prefetchTracker,
            ExecutorService prefetchExecutor
        ) {
            this.segmentPool = segmentPool;
            this.blockCache = blockCache;
            this.maxCacheBlocks = maxCacheBlocks;
            this.readAheadQueueSize = readAheadQueueSize;
            this.sharedReadaheadWorker = sharedReadaheadWorker;
            this.telemetry = telemetry;
            this.removalExecutor = removalExecutor;
            this.readAheadExecutor = readAheadExecutor;
            this.radixBlockTableRegistry = radixBlockTableRegistry;
            this.prefetchTracker = prefetchTracker;
            this.prefetchExecutor = prefetchExecutor;
        }

        /**
         * Returns the node-shared prefetch tracker used by the Lucene {@code IndexInput.prefetch()} path.
         * Its executor is a dedicated {@link ForkJoinPool}; the tracker also provides in-flight dedup,
         * back-pressure, and prefetch statistics.
         *
         * @return the shared prefetch tracker
         */
        public PrefetchTracker getPrefetchTracker() {
            return prefetchTracker;
        }

        /**
         * Returns the node-shared registry of per-file L1 RadixBlockTables. Wired to the shared
         * block cache's eviction listener so L2 evictions clear the corresponding L1 entry.
         *
         * @return the shared RadixBlockTableRegistry
         */
        public RadixBlockTableRegistry getRadixBlockTableRegistry() {
            return radixBlockTableRegistry;
        }

        /**
         * Returns the shared memory segment pool.
         *
         * @return the segment pool
         */
        public Pool<RefCountedByteBuffer> getSegmentPool() {
            return segmentPool;
        }

        /**
         * Returns the shared block cache.
         *
         * @return the block cache
         */
        public BlockCache<RefCountedByteBuffer> getBlockCache() {
            return blockCache;
        }

        /**
         * Returns the maximum number of blocks that can be cached.
         *
         * @return the maximum cache blocks
         */
        public long getMaxCacheBlocks() {
            return maxCacheBlocks;
        }

        /**
         * Returns the calculated read-ahead queue size.
         *
         * @return the read-ahead queue size
         */
        public int getReadAheadQueueSize() {
            return readAheadQueueSize;
        }

        /**
         * Returns the shared read-ahead worker.
         * This worker is shared across all shards/directories with a single queue and executor pool.
         *
         * @return the shared read-ahead worker
         */
        public Worker getSharedReadaheadWorker() {
            return sharedReadaheadWorker;
        }

        /**
         * Returns the shared read-ahead executor service.
         * This executor is shared across all per-shard workers for thread reuse while maintaining queue isolation.
         *
         * @return the read-ahead executor service
         */
        public ExecutorService getReadAheadExecutor() {
            return readAheadExecutor;
        }

        /**
         * Closes the shared pool resources, stops the telemetry thread, and shuts down executors.
         */
        @Override
        public void close() {
            if (telemetry != null) {
                telemetry.close();
            }
            if (sharedReadaheadWorker != null) {
                try {
                    sharedReadaheadWorker.close();
                } catch (Exception e) {
                    LOGGER.warn("Error closing shared readahead worker", e);
                }
            }
            if (removalExecutor != null) {
                removalExecutor.shutdown();
                try {
                    if (!removalExecutor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                        removalExecutor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    removalExecutor.shutdownNow();
                }
            }
            if (readAheadExecutor != null) {
                readAheadExecutor.shutdown();
                try {
                    if (!readAheadExecutor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                        readAheadExecutor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    readAheadExecutor.shutdownNow();
                }
            }
            if (prefetchExecutor != null) {
                prefetchExecutor.shutdown();
                try {
                    if (!prefetchExecutor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                        prefetchExecutor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    prefetchExecutor.shutdownNow();
                }
            }
        }
    }

    /**
     * Autocloseable telemetry thread for periodic pool statistics logging.
     */
    private static class TelemetryThread implements Closeable {
        private final Thread thread;
        private final Pool<RefCountedByteBuffer> pool;
        private final BlockCache<RefCountedByteBuffer> blockCache;
        private final RadixBlockTableRegistry radixBlockTableRegistry;
        private final PrefetchTracker prefetchTracker;

        TelemetryThread(
            Pool<RefCountedByteBuffer> pool,
            BlockCache<RefCountedByteBuffer> blockCache,
            RadixBlockTableRegistry radixBlockTableRegistry,
            PrefetchTracker prefetchTracker
        ) {
            this.pool = pool;
            this.blockCache = blockCache;
            this.radixBlockTableRegistry = radixBlockTableRegistry;
            this.prefetchTracker = prefetchTracker;
            this.thread = new Thread(this::run);
            this.thread.setDaemon(true);
            this.thread.setName("DirectIOBufferPoolStatsLogger");
            this.thread.start();
        }

        private void run() {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(Duration.ofMinutes(5));
                    publishStats();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (Throwable t) {
                    LOGGER.warn("Panic in telemetry buffer stats logger", t);
                }
            }
        }

        private void publishStats() {
            try {
                pool.recordStats();
                blockCache.recordStats();
                if (radixBlockTableRegistry != null) {
                    radixBlockTableRegistry.recordStats();
                }
                if (prefetchTracker != null) {
                    LOGGER.info(prefetchTracker.stats());
                }
            } catch (Exception e) {
                LOGGER.warn("Failed to log cache/pool stats", e);
            }
        }

        @Override
        public void close() {
            thread.interrupt();
            try {
                thread.join(5000); // Wait up to 5 seconds for graceful shutdown
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Initialized the MemorySegmentPool and BlockCache.
     *
     * @param settings the node settings for configuration
     * @return SharedPoolResources containing the initialized pool and cache
     */
    public static PoolResources build(Settings settings) {
        long reservedPoolSizeInBytes = PoolSizeCalculator.calculatePoolSize(settings);

        reservedPoolSizeInBytes = (reservedPoolSizeInBytes / CACHE_BLOCK_SIZE) * CACHE_BLOCK_SIZE;
        long maxBlocks = reservedPoolSizeInBytes / CACHE_BLOCK_SIZE;

        // GC headroom fraction drives the pool's allocation limit (zombie-buffer tolerance).
        double gcHeadroomFraction = PoolSizeCalculator.getGcHeadroomFraction(settings);

        MemorySegmentPool segmentPool = new MemorySegmentPool(reservedPoolSizeInBytes, CACHE_BLOCK_SIZE, gcHeadroomFraction);
        LOGGER
            .info(
                "Creating shared pool with sizeBytes={}, segmentSize={}, totalSegments={}, gcHeadroomFraction={}",
                reservedPoolSizeInBytes,
                CACHE_BLOCK_SIZE,
                maxBlocks,
                gcHeadroomFraction
            );

        // 1:1 cache:pool sizing for the GC-managed pool — the cache holds as many blocks as the
        // pool can allocate (cache evictions are what release pool memory via GC). No warmup:
        // direct ByteBuffers are allocated on demand and reclaimed by the Cleaner.
        long maxCacheBlocks = maxBlocks;

        // Calculate read-ahead queue size based on cache capacity
        // Pool constraint not needed since cache evictions automatically release pool memory
        int readAheadQueueSize = ReadAheadSizingPolicy.calculateQueueSize(maxCacheBlocks);
        LOGGER.info("Calculated read-ahead queue size={} (cache={} blocks)", readAheadQueueSize, maxCacheBlocks);

        // Dedicated prefetch executor for the Lucene IndexInput.prefetch() path. A ForkJoinPool is used
        // (rather than an OpenSearch thread pool) because its work-stealing deque has a much lower
        // task-submission latency, and prefetch submission sits on the hot read path where time-to-submit
        // dominates.
        int prefetchThreads = OpenSearchExecutors.allocatedProcessors(settings) * 4;
        int prefetchQueueSize = prefetchThreads * 1000;
        LOGGER
            .info(
                "Prefetch ForkJoinPool: threads={}, maxInflight={}, allocatedProcessors={}",
                prefetchThreads,
                prefetchQueueSize,
                OpenSearchExecutors.allocatedProcessors(settings)
            );
        ForkJoinPool.ForkJoinWorkerThreadFactory prefetchThreadFactory = fjp -> {
            ForkJoinWorkerThread t = ForkJoinPool.defaultForkJoinWorkerThreadFactory.newThread(fjp);
            t.setName("prefetch-worker-" + t.getPoolIndex());
            t.setDaemon(true);
            return t;
        };
        ExecutorService prefetchExecutor = new ForkJoinPool(prefetchThreads, prefetchThreadFactory, null, false);
        PrefetchTracker prefetchTracker = new PrefetchTracker(prefetchExecutor, prefetchQueueSize);

        // Initialize shared cache with removal listener and get its executor
        BlockCacheBuilder.CacheWithExecutor<RefCountedByteBuffer, RefCountedByteBuffer> cacheWithExecutor = BlockCacheBuilder
            .build(CACHE_INITIAL_SIZE, maxCacheBlocks, prefetchTracker);
        BlockCache<RefCountedByteBuffer> blockCache = cacheWithExecutor.getCache();
        java.util.concurrent.ThreadPoolExecutor removalExecutor = cacheWithExecutor.getExecutor();
        LOGGER.info("Creating shared block cache with blocks={}", maxCacheBlocks);

        // Wire the cache-size supplier so the pool's GC-debt monitor can compute the zombie
        // (GC-pending) buffer count = buffersInUse - cacheEntries.
        segmentPool.setCacheEntriesSupplier(blockCache::getCacheSize);

        // Wire the throttle-engaged release hook: when the pool's memory-pressure throttle engages,
        // shed ~10% of the coldest cached blocks so their pooled buffers become reclaimable and the
        // throttle can clear. Without this the cache (which evicts by entry count, not memory) never
        // releases memory under pressure, so the throttle stays stuck and every recovery retry fails
        // → shard RED. Cooldown-gated inside the pool to avoid thrashing.
        segmentPool.setOnThrottleEngagedHook(() -> blockCache.evictColdestFraction(0.10));

        // Wire the PROACTIVE-shrink primitive (preventive, fires before the throttle when the pool is on a
        // filling trajectory) to the same coldest-eviction mechanism, plus the original cache capacity for
        // the monitor's slack floor. Gated by the (default-off) proactive_shrink_enabled cluster setting.
        segmentPool.setProactiveShrink(blockCache::evictColdestFraction, maxCacheBlocks);
        // Seed the proactive monitor from the current (default-off) cluster-setting value so a pool built
        // AFTER the setting was already flipped picks up the right state; later runtime toggles go through
        // CryptoDirectoryFactory.setProactiveShrinkEnabled to the live monitor.
        segmentPool.proactiveMonitor().setEnabled(org.opensearch.index.store.CryptoDirectoryFactory.isProactiveShrinkEnabled());

        // Node-shared registry of per-file L1 RadixBlockTables. Wire it to the shared cache's
        // eviction listener so that when the Caffeine L2 cache evicts a block, the matching L1
        // (RadixBlockTable) slot is cleared BEFORE the value is closed — keeping L1 coherent
        // with L2 (RefCountedByteBuffer has no generation counter for the L1 to detect staleness).
        RadixBlockTableRegistry radixBlockTableRegistry = new RadixBlockTableRegistry();
        blockCache.setEvictionListener(radixBlockTableRegistry::onEviction);

        // Read-ahead is DISABLED — use a no-op worker so no threads are spawned, no queue is
        // maintained, and no schedule() call ever queues work. Under concurrent search + peer
        // recovery, the async QueuingWorker's lifecycle can race with shard-close: a still-live
        // IndexInput keeps calling schedule() after the worker is closed, producing a large volume
        // of "Attempted schedule on closed worker" DEBUG lines. Bypassing the whole path eliminates
        // that noise and removes the race exposure. Re-enable by restoring the
        // QueuingWorker + ExecutorService constructor below.
        ExecutorService readAheadExecutor = null;
        Worker sharedReadaheadWorker = new NoopWorker();
        LOGGER.info("Read-ahead DISABLED — using NoopWorker (queueSize={}, threads=0)", readAheadQueueSize);

        // Start telemetry
        TelemetryThread telemetry = new TelemetryThread(segmentPool, blockCache, radixBlockTableRegistry, prefetchTracker);

        return new PoolResources(
            segmentPool,
            blockCache,
            maxCacheBlocks,
            readAheadQueueSize,
            sharedReadaheadWorker,
            telemetry,
            removalExecutor,
            readAheadExecutor,
            radixBlockTableRegistry,
            prefetchTracker,
            prefetchExecutor
        );
    }
}
