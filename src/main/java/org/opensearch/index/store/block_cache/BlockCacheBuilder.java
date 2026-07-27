/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.util.concurrent.OpenSearchExecutors;
import org.opensearch.common.util.concurrent.ThreadContext;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;

/**
 * Builder for creating block caches with proper lifecycle management.
 */
public final class BlockCacheBuilder {

    private static final Logger LOGGER = LogManager.getLogger(BlockCacheBuilder.class);

    private BlockCacheBuilder() {}

    /**
     * Result containing both the cache and the executor that must be shut down
     * on node closure.
     *
     * @param <T> the type of cached block values
     * @param <V> the type returned by the block loader
     */
    public static class CacheWithExecutor<T extends AutoCloseable, V> {
        private final CaffeineBlockCache<T, V> cache;
        private final ThreadPoolExecutor executor;
        private final PrefetchTracker prefetchTracker;

        CacheWithExecutor(CaffeineBlockCache<T, V> cache, ThreadPoolExecutor executor) {
            this(cache, executor, null);
        }

        CacheWithExecutor(CaffeineBlockCache<T, V> cache, ThreadPoolExecutor executor, PrefetchTracker prefetchTracker) {
            this.cache = cache;
            this.executor = executor;
            this.prefetchTracker = prefetchTracker;
        }

        /**
         * Returns the configured block cache.
         *
         * @return the block cache instance
         */
        public CaffeineBlockCache<T, V> getCache() {
            return cache;
        }

        /**
         * Returns the executor used for asynchronous cache removal operations.
         * This executor must be shut down when the cache is no longer needed.
         *
         * @return the thread pool executor
         */
        public ThreadPoolExecutor getExecutor() {
            return executor;
        }

        /**
         * Returns the shared prefetch tracker wired into this cache, or {@code null} if prefetch was
         * not configured. The owning {@link org.opensearch.index.store.pool.PoolBuilder} is responsible
         * for shutting down the tracker's executor on node closure.
         *
         * @return the prefetch tracker, or {@code null}
         */
        public PrefetchTracker getPrefetchTracker() {
            return prefetchTracker;
        }
    }

    /**
     * Creates a block cache with the specified capacity and removal handling.
     *
     * @param <T> the type of cached block values
     * @param <V> the type returned by the block loader
     * @param initialCapacity initial capacity hint for the cache
     * @param maxBlocks maximum number of blocks to cache
     * @return CacheWithExecutor containing the configured cache and its executor
     */
    public static <T extends AutoCloseable, V> CacheWithExecutor<T, V> build(int initialCapacity, long maxBlocks) {
        return build(initialCapacity, maxBlocks, null);
    }

    /**
     * Creates a block cache with the specified capacity, removal handling, and prefetch tracker.
     *
     * @param <T> the type of cached block values
     * @param <V> the type returned by the block loader
     * @param initialCapacity initial capacity hint for the cache
     * @param maxBlocks maximum number of blocks to cache
     * @param prefetchTracker shared tracker for async prefetch submission/dedup/stats (may be null)
     * @return CacheWithExecutor containing the configured cache, its removal executor, and the tracker
     */
    public static <T extends AutoCloseable, V> CacheWithExecutor<T, V> build(
        int initialCapacity,
        long maxBlocks,
        PrefetchTracker prefetchTracker
    ) {
        ThreadPoolExecutor removalExec = OpenSearchExecutors
            .newScaling(
                "block-cache-maint",
                4,
                8,
                60L,
                TimeUnit.SECONDS,
                OpenSearchExecutors.daemonThreadFactory("block-cache-maint"),
                new ThreadContext(org.opensearch.common.settings.Settings.EMPTY)
            );

        // Shared reference for L1 eviction notification. The removal listener lambda reads
        // from this reference; CaffeineBlockCache sets it via setEvictionListener(). This is
        // the coherence path that clears stale RadixBlockTable (L1) pointers when the
        // Caffeine L2 cache evicts a block — required because RefCountedByteBuffer carries
        // no generation counter for the L1 to detect staleness on its own.
        AtomicReference<BlockCache.EvictionListener> evictionListenerRef = new AtomicReference<>();

        // Path -> keyset index so invalidate(Path) is O(K-file), not an O(N-cache) scan.
        // Trimmed by the Caffeine removal listener below so every eviction path stays consistent.
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary = new ConcurrentHashMap<>(8192, 0.75f, 64);

        // Forward reference so the removal listener can consult the primary cache.
        AtomicReference<Cache<BlockCacheKey, BlockCacheValue<T>>> cacheRef = new AtomicReference<>();

        Cache<BlockCacheKey, BlockCacheValue<T>> cache = Caffeine
            .newBuilder()
            .initialCapacity(initialCapacity)
            .recordStats()
            .maximumSize(maxBlocks)
            .removalListener((BlockCacheKey key, BlockCacheValue<T> value, RemovalCause cause) -> {
                if (value != null) {
                    // Notify L1 eviction listener BEFORE closing the segment, so the stale
                    // L1 pointer is cleared and future reads see a clean miss.
                    BlockCache.EvictionListener listener = evictionListenerRef.get();
                    if (listener != null && key instanceof FileBlockCacheKey fbk) {
                        try {
                            listener.onEviction(fbk.filePath(), fbk.fileOffset());
                        } catch (Exception e) {
                            LOGGER.warn("L1 eviction notification failed for {}", key, e);
                        }
                    }

                    // Trim the secondary for every eviction cause through one path.
                    // Guard: skip the trim if the primary still holds the key. The removal listener
                    // fires asynchronously — a concurrent re-insert would otherwise leave the
                    // secondary untracking a live entry, so invalidate(Path) would miss it and stale
                    // ciphertext could persist for a recreated path (AES-CTR reads decrypt to garbage
                    // → CRC / CorruptIndexException).
                    Cache<BlockCacheKey, BlockCacheValue<T>> primary = cacheRef.get();
                    if (key instanceof FileBlockCacheKey fbk && (primary == null || !primary.asMap().containsKey(key))) {
                        secondary.computeIfPresent(fbk.filePath(), (p, keys) -> {
                            keys.remove(key);
                            return keys.isEmpty() ? null : keys;
                        });
                    }

                    removalExec.execute(() -> {
                        try {
                            value.close();
                        } catch (Throwable t) {
                            LOGGER.warn("Failed to close cached value during removal {}", key, t);
                        }
                    });
                }
            })
            .build();

        // Publish cache ref so the removal listener can consult primary presence. Listener can't
        // fire before .build() returns; the null-guard in the listener is defensive.
        cacheRef.set(cache);

        // Loader is null here because this creates a shared cache instance.
        // Per-directory caches will wrap this cache with their own loaders
        // that provide directory-specific decryption keys.
        CaffeineBlockCache<T, V> caffeineBlockCache = new CaffeineBlockCache<>(
            cache,
            null,
            maxBlocks,
            evictionListenerRef,
            secondary,
            prefetchTracker
        );
        return new CacheWithExecutor<>(caffeineBlockCache, removalExec, prefetchTracker);
    }
}
