/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tracks prefetch deduplication state, statistics, and async submission for the
 * {@link BlockCache#loadMissingBlocks} path.
 *
 * <p>Encapsulates three concerns:
 * <ul>
 * <li><b>Async submission</b> — prefetch work is handed to an {@link Executor} (a
 * {@link java.util.concurrent.ForkJoinPool} in production) so the calling read thread never blocks on
 * prefetch I/O. A ForkJoinPool is used because its work-stealing deque has a far lower task-submission
 * latency than the array/linked-queue backed OpenSearch thread pools, and prefetch submission sits on the
 * hot read path.</li>
 * <li><b>Deduplication</b> — an in-flight map prevents two concurrent prefetch tasks from loading the same
 * block twice.</li>
 * <li><b>Back-pressure</b> — submissions are dropped once {@code maxInflight} tasks are outstanding, so a
 * slow disk cannot let prefetch work pile up unbounded.</li>
 * </ul>
 *
 * @opensearch.internal
 */
public class PrefetchTracker {

    private final ConcurrentHashMap<BlockCacheKey, Boolean> inflight = new ConcurrentHashMap<>();
    private final AtomicInteger inflightCount = new AtomicInteger();
    private final Executor executor;

    private final AtomicLong prefetchCalls = new AtomicLong();
    private final AtomicLong blocksRequested = new AtomicLong();
    private final AtomicLong blocksLoaded = new AtomicLong();
    private final AtomicLong blocksDeduped = new AtomicLong();
    private final AtomicLong blocksCacheHit = new AtomicLong();
    private final AtomicLong prefetchTimeNs = new AtomicLong();
    private final AtomicLong executeRejections = new AtomicLong();

    private final int maxInflight;

    // Master switch, defaults on. Kept as a plain volatile so an operator-facing cluster setting can be
    // wired to it later without touching the hot path.
    private volatile boolean enabled = true;

    /**
     * Creates a prefetch tracker with the given async executor.
     *
     * @param executor the executor for async prefetch operations (must not be null)
     * @param maxInflight maximum in-flight prefetch tasks before dropping new submissions
     */
    public PrefetchTracker(Executor executor, int maxInflight) {
        this.executor = executor;
        this.maxInflight = maxInflight;
    }

    /**
     * Creates a prefetch tracker with a default in-flight cap of 10,000 tasks.
     *
     * @param executor the executor for async prefetch operations (must not be null)
     */
    public PrefetchTracker(Executor executor) {
        this(executor, 10_000);
    }

    /**
     * Enables or disables prefetch submission at runtime.
     *
     * @param enabled {@code true} to allow submissions, {@code false} to drop them
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return whether prefetch submission is currently enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Submits a task for async prefetch execution.
     * Drops the task if prefetch is disabled or too many operations are already in-flight.
     *
     * @param task the runnable to execute
     */
    public void execute(Runnable task) {
        if (!enabled) {
            return;
        }
        if (inflightCount.get() > maxInflight) {
            executeRejections.incrementAndGet();
            return;
        }
        executor.execute(task);
    }

    /**
     * Attempts to mark a block as in-flight for prefetch.
     *
     * @param key the block cache key
     * @return true if newly added (should be loaded), false if already in-flight (deduped)
     */
    public boolean putIfAbsent(BlockCacheKey key) {
        if (inflight.putIfAbsent(key, Boolean.TRUE) == null) {
            inflightCount.incrementAndGet();
            return true;
        }
        blocksDeduped.incrementAndGet();
        return false;
    }

    /**
     * Clears the in-flight marker for a block once its prefetch load completes.
     *
     * @param key the block cache key
     */
    public void remove(BlockCacheKey key) {
        if (inflight.remove(key) != null) {
            inflightCount.decrementAndGet();
        }
    }

    /**
     * @return the number of prefetch loads currently in-flight
     */
    public int size() {
        return inflightCount.get();
    }

    /**
     * @return whether there are no prefetch loads in-flight
     */
    public boolean isEmpty() {
        return inflightCount.get() == 0;
    }

    /**
     * Clears all in-flight state. Intended for shutdown / test reset.
     */
    public void clear() {
        inflight.clear();
        inflightCount.set(0);
    }

    /**
     * Records that a prefetch call requesting {@code blockCount} blocks was made.
     *
     * @param blockCount number of blocks requested by the call
     */
    public void recordPrefetchCall(long blockCount) {
        prefetchCalls.incrementAndGet();
        blocksRequested.addAndGet(blockCount);
    }

    /**
     * Records the wall-clock time spent submitting/handling a prefetch call.
     *
     * @param nanos elapsed nanoseconds
     */
    public void recordPrefetchTimeNs(long nanos) {
        prefetchTimeNs.addAndGet(nanos);
    }

    /**
     * Records that {@code count} blocks were actually loaded from disk.
     *
     * @param count number of blocks loaded
     */
    public void recordBlocksLoaded(long count) {
        blocksLoaded.addAndGet(count);
    }

    /**
     * Records that {@code count} requested blocks were already cached.
     *
     * @param count number of cache hits
     */
    public void recordCacheHits(long count) {
        blocksCacheHit.addAndGet(count);
    }

    /**
     * @return a formatted one-line summary of prefetch statistics
     */
    public String stats() {
        long calls = prefetchCalls.get();
        long requested = blocksRequested.get();
        long loaded = blocksLoaded.get();
        long deduped = blocksDeduped.get();
        long cacheHit = blocksCacheHit.get();
        long timeMs = prefetchTimeNs.get() / 1_000_000;
        long rejections = executeRejections.get();
        double loadRatio = requested > 0 ? (100.0 * loaded / requested) : 0;
        return String
            .format(
                "Prefetch[calls=%d, requested=%d, loaded=%d, deduped=%d, cacheHit=%d, loadRatio=%.2f%%, timeMs=%d, inflight=%d, rejections=%d]",
                calls,
                requested,
                loaded,
                deduped,
                cacheHit,
                loadRatio,
                timeMs,
                inflight.size(),
                rejections
            );
    }

    public long getCalls() {
        return prefetchCalls.get();
    }

    public long getBlocksRequested() {
        return blocksRequested.get();
    }

    public long getBlocksLoaded() {
        return blocksLoaded.get();
    }

    public long getBlocksDeduped() {
        return blocksDeduped.get();
    }

    public long getBlocksCacheHit() {
        return blocksCacheHit.get();
    }

    public long getPrefetchTimeNs() {
        return prefetchTimeNs.get();
    }

    public long getExecuteRejections() {
        return executeRejections.get();
    }

    // Testing only
    void resetStats() {
        prefetchCalls.set(0);
        blocksRequested.set(0);
        blocksLoaded.set(0);
        blocksDeduped.set(0);
        blocksCacheHit.set(0);
        prefetchTimeNs.set(0);
        executeRejections.set(0);
    }
}
