/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import java.util.LinkedHashMap;
import java.util.Map;

import org.opensearch.search.profile.ProfileMetric;

/**
 * A {@link ProfileMetric} that records a distribution of per-sample values (e.g. per-block disk-read
 * latency in ns, or per-read size in bytes) and emits count/total/min/max/p50/p90/p99.
 *
 * <p><b>Dependency-free, log-bucketed.</b> Each sample maps to a bucket ~10% wider than the last, so
 * percentiles carry ~10% relative error — plenty for a "where does the time go" diagnostic. {@code min}
 * and {@code max} are tracked exactly (not bucketed). No HdrHistogram dependency, no version-set change.
 *
 * <p><b>Threading.</b> Under intra-segment concurrency the same leaf breakdown is shared across slice
 * threads, so {@code record} and {@code toBreakdownMap} are synchronized. Only runs under profiling.
 *
 * <p><b>Concurrent-search caveat.</b> {@code toBreakdownMap()} returns one {@code long} per key, and the
 * core's concurrent-segment-search path SUMS same-named keys across leaves/slices. Summing is correct for
 * {@code _count} and {@code _total} (so avg = total/count is always valid) but MEANINGLESS for
 * {@code _min/_max/_p50/_p90/_p99}. Therefore percentile keys are trustworthy ONLY when profiling with
 * {@code search.concurrent_segment_search.mode=none} (one breakdown per query-node sees every sample).
 * Always take percentile readings on single-thread profiling runs.
 */
public final class CryptoHistogramMetric extends ProfileMetric {

    // idx = 1 + floor(ln(value) * SCALE); SCALE = 1/ln(1.1) => each bucket ~10% wider than the last.
    private static final double SCALE = 10.492;
    private static final int BUCKETS = 256;   // covers up to exp(255/SCALE) ~ 4.6e10, ample for ns and bytes

    private final long[] counts = new long[BUCKETS];
    private long count = 0L;
    private long total = 0L;
    private long min = Long.MAX_VALUE;
    private long max = 0L;

    public CryptoHistogramMetric(String name) {
        super(name);
    }

    /** Record one sample (ns, bytes, ...). Non-positive values count toward count/min but bucket 0. */
    public synchronized void record(long value) {
        count++;
        total += value;
        if (value < min)
            min = value;
        if (value > max)
            max = value;
        int idx = (value <= 0) ? 0 : (int) (Math.log(value) * SCALE) + 1;
        if (idx < 0)
            idx = 0;
        else if (idx >= BUCKETS)
            idx = BUCKETS - 1;
        counts[idx]++;
    }

    /** Approximate value at the given percentile (0..1) using the bucket lower bound. */
    private long percentile(double p) {
        if (count == 0)
            return 0L;
        long target = (long) Math.ceil(p * count);
        if (target < 1)
            target = 1;
        long cumulative = 0;
        for (int i = 0; i < BUCKETS; i++) {
            cumulative += counts[i];
            if (cumulative >= target) {
                if (i == 0)
                    return Math.max(0L, min);
                long lo = (long) Math.exp((i - 1) / SCALE);   // lower edge of bucket i
                // Clamp to observed range so a coarse bucket can't report outside [min, max].
                if (lo < min)
                    lo = min;
                if (lo > max)
                    lo = max;
                return lo;
            }
        }
        return max;
    }

    @Override
    public synchronized Map<String, Long> toBreakdownMap() {
        Map<String, Long> m = new LinkedHashMap<>();
        String n = getName();
        // A key equal to the bare metric name is required for the concurrent-segment-search reduce path,
        // which looks up map.get(name) per slice; emit the total under it (sums correctly across slices).
        m.put(n, total);
        m.put(n + "_count", count);
        m.put(n + "_total", total);
        m.put(n + "_min", count == 0 ? 0L : min);
        m.put(n + "_max", max);
        m.put(n + "_p50", percentile(0.50));
        m.put(n + "_p90", percentile(0.90));
        m.put(n + "_p99", percentile(0.99));
        return m;
    }
}
