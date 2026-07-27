/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

/**
 * Generic block cache interface for storing and retrieving blocks of data.
 * 
 * <p>This cache provides efficient storage and retrieval of file blocks with support for
 * asynchronous loading, bulk operations, and cache invalidation. The cache is parameterized
 * by the type {@code T} which represents the cached block data.
 *
 * <p>Implementations should be thread-safe and handle concurrent access appropriately.
 *
 * @param <T> the type of cached block data
 * @opensearch.internal
 */
public interface BlockCache<T> {

    /**
     * Callback invoked when a block is evicted from the cache.
     * Used to notify L1 caches (RadixBlockTable) so they can clear stale entries.
     *
     * <p>This is the coherence mechanism for the GC-managed {@code RefCountedByteBuffer} L1
     * design: because {@code RefCountedByteBuffer} carries no generation counter, the L1
     * (RadixBlockTable) cannot detect a stale entry on its own. The L2 cache notifies the L1
     * here, on eviction, so the L1 drops the stale pointer and future reads see a clean miss.
     */
    @FunctionalInterface
    interface EvictionListener {
        void onEviction(Path path, long blockOffset);
    }

    /**
     * Registers a listener that is notified when blocks are evicted from this cache.
     * The listener is called before the evicted value is closed.
     *
     * @param listener the eviction listener
     */
    default void setEvictionListener(EvictionListener listener) {
        // no-op by default; implementations that support eviction notification override this
    }

    /**
     * Returns the block if cached, or null if absent.
     *
     * @param key the cache key identifying the block
     * @return the cached block value, or null if not present
     */
    BlockCacheValue<T> get(BlockCacheKey key);

    /**
     * Returns the block, loading it via {@code BlockLoader} if absent.
     * 
     * @param key the cache key identifying the block
     * @return the block value, either from cache or newly loaded
     * @throws IOException if the block cannot be loaded
     */
    BlockCacheValue<T> getOrLoad(BlockCacheKey key) throws IOException;

    /**
     * Asynchronously load the block into the cache if not present.
     *
     * @param key the cache key identifying the block to prefetch
     */
    void prefetch(BlockCacheKey key);

    /**
     * Put a block into the cache.
     *
     * @param key the cache key for the block
     * @param value the block value to cache
     */
    void put(BlockCacheKey key, BlockCacheValue<T> value);

    /**
     * Evict a block from the cache.
     *
     * @param key the cache key for the block to evict
     */
    void invalidate(BlockCacheKey key);

    /**
     * Evict all blocks for a given normalized file path.
     *
     * @param normalizedFilePath the file path whose blocks should be evicted
     */
    void invalidate(Path normalizedFilePath);

    /**
     * Evict all blocks whose file paths start with the given directory path.
     * This is useful for clearing cache entries when an index or shard is deleted.
     *
     * @param directoryPath the directory path prefix to match
     */
    void invalidateByPathPrefix(Path directoryPath);

    /**
     * Clear all blocks from the cache.
     */
    void clear();

    /**
     * Evict approximately the given fraction (0.0–1.0) of currently-cached blocks to release memory
     * under pressure. Implementations should evict the coldest entries first and run their normal
     * removal/eviction listeners so the backing buffers become reclaimable. Used by the pool's
     * memory-pressure throttle to actively shed memory so the throttle can clear (see
     * {@code MemorySegmentPool} throttle-engaged hook). Default no-op.
     *
     * @param fraction fraction of current entries to evict, clamped to [0,1]
     * @return the number of entries evicted
     */
    default long evictColdestFraction(double fraction) {
        return 0L;
    }

    /**
     * Load multiple blocks for prefetch/readahead with a short timeout to fail fast when pool is under pressure.
     * Uses a 50ms timeout for pool segment acquisition - prefetch should not block critical I/O.
     *
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to read
     * @return map of cache keys to cache values for blocks that were successfully loaded into the cache
     * @throws IOException if loading fails (including pool timeout, which is expected under pressure)
     */
    Map<BlockCacheKey, BlockCacheValue<T>> loadForPrefetch(Path filePath, long startOffset, long blockCount) throws IOException;

    /**
     * Prefetch a range of blocks for the Lucene {@code IndexInput.prefetch()} path.
     *
     * <p>Unlike {@link #loadForPrefetch} (a single synchronous bulk read used by the read-ahead worker), this
     * method is asynchronous and fire-and-forget: the missing blocks are submitted to a dedicated prefetch
     * executor (a {@link java.util.concurrent.ForkJoinPool}) so the calling read thread is never blocked on
     * prefetch I/O. Blocks already cached or already being prefetched are skipped via the shared
     * {@link PrefetchTracker}. Submissions are dropped under back-pressure rather than queued unbounded.
     *
     * <p>Implementations without a configured prefetch tracker/executor may load the range synchronously as a
     * best-effort fallback.
     *
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to prefetch
     * @throws IOException if a synchronous fallback load fails
     */
    default void loadMissingBlocks(Path filePath, long startOffset, long blockCount) throws IOException {
        // Default: no async prefetch support. Implementations that wire a PrefetchTracker override this.
        loadForPrefetch(filePath, startOffset, blockCount);
    }

    /**
     * Returns cache statistics as a formatted string.
     *
     * @return string representation of cache statistics including hit/miss ratios, sizes, etc.
     */
    String cacheStats();

    /**
     * record cache stats
     */
    void recordStats();

    /**
     * Returns the cache hit rate as a value between 0.0 and 1.0.
     *
     * @return hit rate (hits / (hits + misses))
     */
    double getHitRate();

    /**
     * Returns the current estimated size of the cache.
     *
     * @return number of entries in the cache
     */
    long getCacheSize();

    /**
     * Returns the cumulative count of cache hits.
     *
     * @return total number of cache hits since cache creation
     */
    long hitCount();

    /**
     * Returns the cumulative count of cache misses.
     *
     * @return total number of cache misses since cache creation
     */
    long missCount();
}
