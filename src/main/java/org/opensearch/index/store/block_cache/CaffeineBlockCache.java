/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.metrics.CryptoMetricsService;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.stats.CacheStats;

/**
 * A Caffeine-based implementation of {@link BlockCache} that provides efficient caching
 * of file blocks with automatic loading, eviction, and cleanup.
 * 
 * <p>This cache integrates with Caffeine's high-performance caching library to provide
 * concurrent, thread-safe access to cached blocks. It supports automatic loading via
 * {@link BlockLoader} instances, bulk operations for efficient I/O, and proper cleanup
 * of cached resources through reference counting.
 *
 * @param <T> the type of cached block data
 * @param <V> the type of data loaded by the BlockLoader
 * @opensearch.internal
 */
@SuppressForbidden(reason = "uses custom DirectIO")
public final class CaffeineBlockCache<T, V> implements BlockCache<T> {
    private static final Logger LOGGER = LogManager.getLogger(CaffeineBlockCache.class);

    private final Cache<BlockCacheKey, BlockCacheValue<T>> cache;
    private final BlockLoader<V> blockLoader;

    /**
     * Shared reference to the eviction listener, set by {@link #setEvictionListener}.
     * Read by the Caffeine removal listener (lambda in {@link BlockCacheBuilder}) to notify
     * L1 caches (RadixBlockTable) when blocks are evicted, so stale L1 pointers are cleared.
     */
    private final AtomicReference<EvictionListener> evictionListenerRef;

    /**
     * File path → set of cached block keys for that path. Populated at every insertion site here;
     * trimmed by the removal listener in {@link BlockCacheBuilder}. Enables {@link #invalidate(Path)}
     * to complete in O(K-file) instead of an O(N-cache) scan.
     */
    private final ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary;

    /**
     * Pool-acquire timeout (ms) for a single-block prefetch load. Kept intentionally short so prefetch
     * fails fast and never contends with critical on-demand loads when the segment pool is under pressure.
     */
    private static final long PREFETCH_POOL_TIMEOUT_MS = 5;

    /**
     * Shared prefetch tracker providing async submission (ForkJoinPool), in-flight dedup, back-pressure,
     * and statistics for the {@link #loadMissingBlocks} path. May be {@code null} for caches that were
     * built without prefetch support (e.g. some tests); in that case prefetch falls back to a synchronous
     * best-effort load.
     */
    private final PrefetchTracker prefetchTracker;

    /**
     * Previous cumulative {@link CacheStats} snapshot, so {@link #recordStats()} can publish the PER-INTERVAL
     * delta (this tick minus last tick) instead of lifetime cumulative counters. Cumulative counters forced the
     * dashboard to use {@code derivative}, which mis-handles JVM-restart counter resets (large negative spikes)
     * and cannot compute a per-interval hit-rate or average-load-time across separate series. Publishing the
     * delta at the source makes the dashboard a plain {@code avg(value)}. Only touched from the single-threaded
     * telemetry tick, so it needs no synchronization.
     */
    private CacheStats previousStats = CacheStats.empty();

    /**
     * Constructs a new CaffeineBlockCache with the specified cache and block loader.
     *
     * @param cache the underlying Caffeine cache instance
     * @param blockLoader the loader used to load blocks when cache misses occur
     * @param maxBlocks the maximum number of blocks to cache (currently unused but kept for API compatibility)
     */
    public CaffeineBlockCache(Cache<BlockCacheKey, BlockCacheValue<T>> cache, BlockLoader<V> blockLoader, long maxBlocks) {
        this(cache, blockLoader, maxBlocks, new AtomicReference<>(), new ConcurrentHashMap<>(), null);
    }

    /**
     * Constructs a CaffeineBlockCache with a shared {@link PrefetchTracker} for the async
     * {@link #loadMissingBlocks} path (fresh eviction-listener ref and secondary index).
     *
     * @param cache the underlying Caffeine cache instance
     * @param blockLoader the loader used to load blocks when cache misses occur
     * @param maxBlocks the maximum number of blocks to cache (currently unused but kept for API compatibility)
     * @param prefetchTracker shared tracker for async prefetch submission, dedup, and stats (may be null)
     */
    public CaffeineBlockCache(
        Cache<BlockCacheKey, BlockCacheValue<T>> cache,
        BlockLoader<V> blockLoader,
        long maxBlocks,
        PrefetchTracker prefetchTracker
    ) {
        this(cache, blockLoader, maxBlocks, new AtomicReference<>(), new ConcurrentHashMap<>(), prefetchTracker);
    }

    /**
     * Per-directory wrapper sharing the underlying cache and eviction/secondary bookkeeping of
     * {@code source}. Used by {@code CryptoDirectoryFactory} to build per-directory decryption
     * wrappers over the shared cache from {@link BlockCacheBuilder}. Reuses {@code source}'s prefetch
     * tracker so all directory caches submit to the same shared async prefetch executor.
     */
    public CaffeineBlockCache(
        Cache<BlockCacheKey, BlockCacheValue<T>> cache,
        BlockLoader<V> blockLoader,
        long maxBlocks,
        CaffeineBlockCache<T, ?> source
    ) {
        this(cache, blockLoader, maxBlocks, source.evictionListenerRef, source.secondary, source.prefetchTracker);
    }

    /**
     * Full constructor with shared eviction-listener ref and secondary path index. Both refs are
     * shared with the {@link BlockCacheBuilder} removal listener so eviction bookkeeping runs
     * through a single code path.
     *
     * @param cache the underlying Caffeine cache instance
     * @param blockLoader the loader used to load blocks when cache misses occur
     * @param maxBlocks the maximum number of blocks to cache (currently unused but kept for API compatibility)
     * @param evictionListenerRef shared reference read by the Caffeine removal listener
     * @param secondary shared path -> keyset index used to short-circuit {@link #invalidate(Path)}
     */
    public CaffeineBlockCache(
        Cache<BlockCacheKey, BlockCacheValue<T>> cache,
        BlockLoader<V> blockLoader,
        long maxBlocks,
        AtomicReference<EvictionListener> evictionListenerRef,
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary
    ) {
        this(cache, blockLoader, maxBlocks, evictionListenerRef, secondary, null);
    }

    /**
     * Full constructor additionally wiring a shared {@link PrefetchTracker} for the async
     * {@link #loadMissingBlocks} path.
     *
     * @param cache the underlying Caffeine cache instance
     * @param blockLoader the loader used to load blocks when cache misses occur
     * @param maxBlocks the maximum number of blocks to cache (currently unused but kept for API compatibility)
     * @param evictionListenerRef shared reference read by the Caffeine removal listener
     * @param secondary shared path -> keyset index used to short-circuit {@link #invalidate(Path)}
     * @param prefetchTracker shared tracker for async prefetch submission, dedup, and stats (may be null)
     */
    public CaffeineBlockCache(
        Cache<BlockCacheKey, BlockCacheValue<T>> cache,
        BlockLoader<V> blockLoader,
        long maxBlocks,
        AtomicReference<EvictionListener> evictionListenerRef,
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary,
        PrefetchTracker prefetchTracker
    ) {
        this.blockLoader = blockLoader;
        this.cache = cache;
        this.evictionListenerRef = evictionListenerRef;
        this.secondary = secondary;
        this.prefetchTracker = prefetchTracker;
    }

    /**
     * Returns the shared prefetch tracker, so per-directory cache wrappers can reuse the same async
     * executor, in-flight dedup map, and statistics as the shared cache.
     *
     * @return the prefetch tracker, or {@code null} if none was configured
     */
    public PrefetchTracker getPrefetchTracker() {
        return prefetchTracker;
    }

    /**
     * Records {@code key} in the secondary index so a later {@code invalidate(Path)} finds it in
     * O(K-file). Called from every insertion site.
     */
    private void trackInsertion(BlockCacheKey key) {
        if (key instanceof FileBlockCacheKey fbk) {
            secondary.computeIfAbsent(fbk.filePath(), p -> ConcurrentHashMap.<BlockCacheKey>newKeySet(32)).add(key);
        }
    }

    @Override
    public void setEvictionListener(EvictionListener listener) {
        evictionListenerRef.set(listener);
    }

    @Override
    public BlockCacheValue<T> get(BlockCacheKey key) {
        return cache.getIfPresent(key);
    }

    /**
    * Retrieves the cached block associated with the given key, or loads it if not present.
    * <p>
    * If the block is present in the cache, it is returned immediately.
    * If the block is absent, the {@link BlockLoader} is invoked to load it. If loading succeeds,
    * the loaded block is inserted into the cache and returned. If loading fails, an exception is thrown.
    * <p>
    * Any {@link IOException} thrown by the loader is propagated, while other exceptions are wrapped
    * in {@link IOException}.
    *
    * @param key  The key identifying the block to retrieve or load.
    * @return The cached or newly loaded block (never null).
    * @throws IOException if the block loading fails with an IO-related error.
    */
    @Override
    public BlockCacheValue<T> getOrLoad(BlockCacheKey key) throws IOException {
        try {
            AtomicBoolean inserted = new AtomicBoolean(false);
            BlockCacheValue<T> value = cache.get(key, k -> {
                try {
                    V segment = blockLoader.load(k);
                    @SuppressWarnings("unchecked")
                    BlockCacheValue<T> result = (BlockCacheValue<T>) segment;
                    inserted.set(true);
                    return result;
                } catch (Exception e) {
                    return handleLoadException(k, e);
                }
            });

            if (value == null) {
                throw new IOException("Failed to load block for key: " + key);
            }

            // Degraded-mode fallback blocks (non-pooled, not memory-accounted) must not persist in
            // the cache. Caffeine's get(key, loader) inserts the loaded value; evict it immediately
            // so only its single in-flight use survives, then hand it back to this caller.
            if (value.isTransient()) {
                cache.invalidate(key);
            } else if (inserted.get()) {
                // Only track newly-inserted keys; cache-hits are already in the secondary.
                trackInsertion(key);
            }

            return value;
        } catch (UncheckedIOException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IOException("Failed to load block for key: " + key, e);
        }
    }

    @Override
    public void prefetch(BlockCacheKey key) {
        try {
            AtomicBoolean inserted = new AtomicBoolean(false);
            BlockCacheValue<T> value = cache.get(key, k -> {
                try {
                    V segment = blockLoader.load(k);
                    // Direct cast - BlockLoader contract guarantees V is BlockCacheValue<T>
                    @SuppressWarnings("unchecked")
                    BlockCacheValue<T> result = (BlockCacheValue<T>) segment;
                    inserted.set(true);
                    return result;
                } catch (Exception e) {
                    return handleLoadException(k, e);
                }
            });
            // A degraded-mode transient buffer (non-pooled, not memory-accounted) must never persist in
            // the cache; cache.get inserts it, so evict it immediately. Mirrors getOrLoad's guard.
            if (value != null && value.isTransient()) {
                cache.invalidate(key);
            } else if (inserted.get()) {
                trackInsertion(key);
            }
        } catch (Exception e) {
            // Prefetch failures are non-fatal - log and continue
            LOGGER.debug("Prefetch failed for key: {}", key, e);
        }
    }

    @Override
    public void put(BlockCacheKey key, BlockCacheValue<T> value) {
        cache.put(key, value);
        trackInsertion(key);
    }

    @Override
    public void invalidate(BlockCacheKey key) {
        cache.invalidate(key);
    }

    @Override
    public void invalidate(Path filePath) {
        Path normalized = filePath.toAbsolutePath().normalize();
        // O(K-file) via the secondary: remove the path's key-set in one shot, avoiding an
        // O(N-cache) scan. The removal listener's own trim becomes a no-op since the Path entry
        // is already gone.
        Set<BlockCacheKey> keys = secondary.remove(normalized);
        if (keys != null && !keys.isEmpty()) {
            // invalidateAll to trigger removal listener for proper segment cleanup
            // note: invalidateAll doesn't effect eviction count.
            cache.invalidateAll(keys);
        }
    }

    @Override
    public void invalidateByPathPrefix(Path directoryPath) {
        Path normalized = directoryPath.toAbsolutePath().normalize();
        // Walk the secondary's O(F) file-key set instead of the O(N-cache) primary — F (distinct
        // files under this directory) is orders of magnitude smaller than N (cached blocks).
        java.util.ArrayList<BlockCacheKey> keysToInvalidate = new java.util.ArrayList<>();
        var it = secondary.entrySet().iterator();
        while (it.hasNext()) {
            var entry = it.next();
            if (entry.getKey().startsWith(normalized)) {
                keysToInvalidate.addAll(entry.getValue());
                it.remove();
            }
        }
        if (!keysToInvalidate.isEmpty()) {
            LOGGER.debug("Invalidating {} cache entries for path prefix: {}", keysToInvalidate.size(), normalized);
            cache.invalidateAll(keysToInvalidate);
        }
    }

    @Override
    public void clear() {
        // note: invalidateAll doesn't effect eviction count.
        cache.invalidateAll();
    }

    /**
     * Bulk load multiple blocks efficiently using a single I/O operation.
     * Similar to getOrLoad() but for a contiguous range of blocks.
     * 
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to read
     * @throws IOException if loading fails (including specific BlockLoader exceptions)
     */
    @Override
    public Map<BlockCacheKey, BlockCacheValue<T>> loadForPrefetch(Path filePath, long startOffset, long blockCount) throws IOException {
        Map<BlockCacheKey, BlockCacheValue<T>> loaded = new LinkedHashMap<>();

        V[] loadedBlocks;

        try {
            // Use 50ms timeout for prefetch - fail fast when pool is under pressure
            loadedBlocks = blockLoader.load(filePath, startOffset, blockCount, 50);

            for (int i = 0; i < loadedBlocks.length; i++) {
                V block = loadedBlocks[i];

                // Defensive: the loader's read-completeness contract guarantees every block up to
                // blockCount is populated (a short read now throws rather than leaving a null tail),
                // but a null entry must never NPE here. Skip it rather than dereference isTransient().
                if (block == null) {
                    continue;
                }

                long blockOffset = startOffset + i * CACHE_BLOCK_SIZE;
                BlockCacheKey key = createBlockKey(filePath, blockOffset);

                // Direct cast - BlockLoader contract guarantees V is BlockCacheValue<T>
                @SuppressWarnings("unchecked")
                BlockCacheValue<T> wrapped = (BlockCacheValue<T>) block;
                loaded.put(key, wrapped);

                if (wrapped.isTransient()) {
                    // Degraded-mode fallback block: hand it to the caller but never cache it
                    // (non-pooled, not memory-accounted).
                    continue;
                }

                if (cache.asMap().putIfAbsent(key, wrapped) != null) {
                    // already cached → release our newly loaded segment as we won't use it
                    // we use decRef() not close() - this segment was never inserted into cache,
                    // so we shouldn't increment generation.
                    wrapped.decRef();
                } else {
                    trackInsertion(key);
                }
            }

        } catch (Exception e) {
            try {
                handleLoadException(createBlockKey(filePath, startOffset), e);
            } catch (UncheckedIOException uie) {
                throw uie.getCause();
            } catch (RuntimeException re) {
                throw new IOException("Failed bulk load: " + filePath, re);
            }
        }

        return loaded;
    }

    /**
     * Asynchronous prefetch entry point for the Lucene {@code IndexInput.prefetch()} path.
     *
     * <p>Submits the missing-block range to the shared {@link PrefetchTracker}'s executor (a ForkJoinPool)
     * and returns immediately, so the calling read thread never blocks on prefetch I/O. The actual loading
     * runs in {@link #loadMissingBlocksSync}, which loads one block at a time and skips blocks already
     * cached or already being prefetched. If no tracker is configured, the range is loaded synchronously as
     * a best-effort fallback.
     */
    @Override
    public void loadMissingBlocks(Path filePath, long startOffset, long blockCount) {
        if (prefetchTracker == null) {
            // No async support wired — best-effort synchronous load (no dedup, no stats).
            loadMissingBlocksSync(filePath, startOffset, blockCount, null);
            return;
        }

        prefetchTracker.recordPrefetchCall(blockCount);
        long t0 = System.nanoTime();
        try {
            prefetchTracker.execute(() -> {
                try {
                    loadMissingBlocksSync(filePath, startOffset, blockCount, prefetchTracker);
                } catch (Exception e) {
                    LOGGER.error("failed to prefetch blocks: path={} offset={} count={}", filePath, startOffset, blockCount, e);
                }
            });
        } catch (Exception e) {
            LOGGER.warn("prefetch task rejected: path={} offset={} count={} e={}", filePath, startOffset, blockCount, e.getMessage());
        } finally {
            prefetchTracker.recordPrefetchTimeNs(System.nanoTime() - t0);
        }
    }

    /**
     * Loads a contiguous range of blocks one at a time, skipping blocks already cached or already in-flight
     * (when a tracker is supplied). Each block is loaded with a short pool-acquire timeout
     * ({@link #PREFETCH_POOL_TIMEOUT_MS}) so prefetch fails fast under pool pressure. Degraded-mode
     * (transient) blocks are never left in the shared cache.
     *
     * @param tracker the prefetch tracker for dedup/stats, or {@code null} for an untracked best-effort load
     */
    private void loadMissingBlocksSync(Path filePath, long startOffset, long blockCount, PrefetchTracker tracker) {
        BlockCacheKey[] keys = new BlockCacheKey[(int) blockCount];
        int keyCount = 0;
        for (int i = 0; i < blockCount; i++) {
            long blockOffset = startOffset + i * CACHE_BLOCK_SIZE;
            BlockCacheKey key = createBlockKey(filePath, blockOffset);
            // Dedup against other in-flight prefetch tasks. Without a tracker, load every block.
            if (tracker == null || tracker.putIfAbsent(key)) {
                keys[keyCount++] = key;
            }
        }

        long[] loaded = { 0 };
        long failed = 0;
        for (int i = 0; i < keyCount; i++) {
            BlockCacheKey key = keys[i];
            try {
                BlockCacheValue<T> value = cache.get(key, k -> {
                    try {
                        V[] result = blockLoader.load(k.filePath(), k.offset(), 1, PREFETCH_POOL_TIMEOUT_MS);
                        @SuppressWarnings("unchecked")
                        BlockCacheValue<T> v = (BlockCacheValue<T>) result[0];
                        loaded[0]++;
                        return v;
                    } catch (Exception e) {
                        return handleLoadException(k, e);
                    }
                });
                // Degraded-mode fallback blocks (non-pooled, not memory-accounted) must never persist in the
                // shared cache — evict immediately, mirroring getOrLoad()'s transient handling.
                if (value != null && value.isTransient()) {
                    cache.invalidate(key);
                }
            } catch (Exception e) {
                LOGGER.warn("Prefetch load failed: path={} offset={}", filePath, key.offset(), e);
                failed++;
            } finally {
                if (tracker != null) {
                    tracker.remove(key);
                }
            }
        }
        if (tracker != null) {
            if (loaded[0] > 0) {
                tracker.recordBlocksLoaded(loaded[0]);
            }
            long cacheHits = keyCount - loaded[0] - failed;
            if (cacheHits > 0) {
                tracker.recordCacheHits(cacheHits);
            }
        }
    }

    // Helper method to create appropriate cache key for file blocks
    private BlockCacheKey createBlockKey(Path filePath, long offset) {
        return new FileBlockCacheKey(filePath, offset);
    }

    private BlockCacheValue<T> handleLoadException(BlockCacheKey key, Exception e) {
        switch (e) {
            case BlockLoader.PoolPressureException ppe -> throw new UncheckedIOException(ppe);
            case BlockLoader.PoolAcquireFailedException pafe -> throw new UncheckedIOException(pafe);
            case BlockLoader.BlockLoadFailedException blfe -> throw new UncheckedIOException(blfe);
            case java.nio.file.NoSuchFileException nsfe -> throw new UncheckedIOException(nsfe);
            case IOException io -> throw new UncheckedIOException(io);
            case RuntimeException rte -> throw rte;
            default -> throw new RuntimeException("Unexpected exception during block load for key: " + key, e);
        }
    }

    @Override
    public String cacheStats() {
        var stats = cache.stats();
        // secondary.size() = distinct files tracked; primary size = cached blocks.
        return String
            .format(
                "Cache[size=%d, secondary_files=%d, hits=%d, misses=%d, hitRate=%.2f%%, loads=%d, evictionCount=%d, avgLoadTime=%.2fms]",
                cache.estimatedSize(),
                secondary.size(),
                stats.hitCount(),
                stats.missCount(),
                stats.hitRate() * 100,
                stats.loadCount(),
                stats.evictionCount(),
                stats.averageLoadPenalty() / 1_000_000.0  // Convert to ms
            );
    }

    /**
     * Get the underlying Caffeine cache instance.
     * This is used for sharing the cache storage across multiple BlockCache instances
     * with different loaders.
     *
     * @return the underlying Caffeine cache instance
     */
    public Cache<BlockCacheKey, BlockCacheValue<T>> getCache() {
        return cache;
    }

    /**
     * Evict ~{@code fraction} of the coldest entries to shed memory under pool pressure. Uses Caffeine's
     * eviction policy to drop the {@code n} least-recently-used entries (which fires the removal listener,
     * so the backing pooled buffers become unreachable and are reclaimed by the Cleaner). Falls back to
     * evicting an arbitrary sample of keys if the eviction policy is unavailable. Best-effort and
     * thread-safe; safe to call from the pool's monitor thread.
     */
    @Override
    public long evictColdestFraction(double fraction) {
        double f = Math.max(0.0, Math.min(1.0, fraction));
        if (f == 0.0) {
            return 0L;
        }
        long size = cache.estimatedSize();
        long toEvict = (long) Math.ceil(size * f);
        if (toEvict <= 0) {
            return 0L;
        }
        var evictionOpt = cache.policy().eviction();
        if (evictionOpt.isPresent()) {
            var eviction = evictionOpt.get();
            // coldest(n) returns the n least-recently-used entries in LRU order.
            var coldestKeys = new java.util.ArrayList<>(eviction.coldest((int) Math.min(toEvict, Integer.MAX_VALUE)).keySet());
            if (!coldestKeys.isEmpty()) {
                cache.invalidateAll(coldestKeys);
                LOGGER.debug("Throttle-driven eviction: evicted {} coldest of ~{} blocks", coldestKeys.size(), size);
                return coldestKeys.size();
            }
        }
        // Fallback: evict an arbitrary slice of current keys.
        var keys = cache.asMap().keySet().stream().limit(toEvict).toList();
        if (!keys.isEmpty()) {
            cache.invalidateAll(keys);
        }
        return keys.size();
    }

    @Override
    public void recordStats() {
        // Publish the PER-INTERVAL delta (since the last tick), not lifetime cumulative counters — see
        // previousStats. delta.hitRate()/averageLoadPenalty() are computed over just this interval's events,
        // so a degrading cache is visible immediately and the dashboard needs no derivative(). size is an
        // instantaneous gauge and is published as-is (not a delta).
        var stats = cache.stats();
        var delta = stats.minus(previousStats);
        previousStats = stats;
        CryptoMetricsService
            .getInstance()
            .recordCacheStats(
                cache.estimatedSize(),                       // instantaneous gauge (not a delta)
                delta.hitCount(),
                delta.missCount(),
                delta.hitRate() * 100,                       // per-interval hit rate
                delta.loadCount(),
                delta.evictionCount(),
                delta.averageLoadPenalty() / 1_000_000.0     // per-interval avg load time, ms
            );
    }

    @Override
    public double getHitRate() {
        return cache.stats().hitRate();
    }

    @Override
    public long getCacheSize() {
        return cache.estimatedSize();
    }

    @Override
    public long hitCount() {
        return cache.stats().hitCount();
    }

    @Override
    public long missCount() {
        return cache.stats().missCount();
    }

}
