/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;

/**
 * Tracks cumulative allocated/reclaimed bytes and derives 1-second rate gauges (bytes/sec).
 *
 * <p>The cumulative totals answer "how much was ever allocated"; the rate gauges answer the
 * operationally useful question "how fast is the pool churning <em>right now</em>" — which
 * distinguishes the two fundamentally different throttle causes during a post-mortem:
 * <ul>
 *   <li><b>allocation rate &gt; reclamation rate</b> — the pool is on a filling trajectory
 *       (workload spike, or reclamation falling behind), the precursor to throttle engagement;</li>
 *   <li><b>reclamation rate lagging</b> — GC has not yet reclaimed freed buffers (zombie buildup).</li>
 * </ul>
 * Without these two rates a "throttle engaged" dashboard cannot tell "add capacity" from
 * "GC/zombie problem." Also the trajectory input to {@link ProactiveMemoryMonitor}.
 *
 * <p>The two cumulative counters are multi-writer ({@link LongAdder}: {@link #onAllocated} on the
 * acquire path, {@link #onReclaimed} on the {@code Cleaner} thread); the snapshot bookkeeping and
 * the rate gauges are written only by the single telemetry/monitor thread that calls
 * {@link #snapshot()} (gauges are {@code volatile} so readers see them).
 *
 * @opensearch.internal
 */
public final class AllocationRateMeter {

    private final LongSupplier clock;
    private final LongAdder allocatedBytesTotal = new LongAdder();
    private final LongAdder reclaimedBytesTotal = new LongAdder();

    private long allocatedAtLastTick = 0L;
    private long reclaimedAtLastTick = 0L;
    private long lastTickNanos = Long.MIN_VALUE / 2;

    // Gauges: telemetry/monitor thread writes, readers (recordStats / PoolView) read.
    private volatile long allocationRateBytesPerSec = 0L;
    private volatile long reclamationRateBytesPerSec = 0L;

    /** @param clock nanosecond time source (swappable for tests); defaults to {@link System#nanoTime}. */
    public AllocationRateMeter(LongSupplier clock) {
        this.clock = clock != null ? clock : System::nanoTime;
    }

    /** Record a successful allocation (allocator thread). */
    public void onAllocated(long bytes) {
        allocatedBytesTotal.add(bytes);
    }

    /** Record a Cleaner-driven reclamation (Cleaner thread). */
    public void onReclaimed(long bytes) {
        reclaimedBytesTotal.add(bytes);
    }

    /**
     * Recompute the 1-second rate gauges from the cumulative deltas since the previous tick. The
     * first call only seeds the baseline (rates stay 0). Single-threaded (telemetry/monitor thread).
     */
    public void snapshot() {
        long allocNow = allocatedBytesTotal.sum();
        long reclmNow = reclaimedBytesTotal.sum();
        long now = clock.getAsLong();
        if (lastTickNanos != Long.MIN_VALUE / 2) {
            long allocDelta = Math.max(0L, allocNow - allocatedAtLastTick);
            long reclmDelta = Math.max(0L, reclmNow - reclaimedAtLastTick);
            long elapsed = Math.max(1L, now - lastTickNanos); // clamp so zero-elapsed cannot divide by zero
            allocationRateBytesPerSec = (long) (allocDelta * 1e9 / elapsed);
            reclamationRateBytesPerSec = (long) (reclmDelta * 1e9 / elapsed);
        }
        allocatedAtLastTick = allocNow;
        reclaimedAtLastTick = reclmNow;
        lastTickNanos = now;
    }

    public long allocationRateBytesPerSec() {
        return allocationRateBytesPerSec;
    }

    public long reclamationRateBytesPerSec() {
        return reclamationRateBytesPerSec;
    }
}
