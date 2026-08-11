/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import java.util.LinkedHashMap;
import java.util.Map;

import org.opensearch.search.profile.ProfileMetric;

/**
 * Accumulates elapsed nanos for a phase that has no per-sample histogram. Unlike a
 * {@link org.opensearch.search.profile.Timer}, it is not summed into a query node's
 * {@code time_in_nanos} by {@code AbstractProfileBreakdown.toNodeTime()} (which only totals
 * {@code Timer} metrics). Emits {@code {name}} (total ns) and {@code {name}_count}.
 *
 * <p>{@link #start()} returns the caller's start timestamp (held in a caller-local), so no start
 * state is shared across threads. {@link #stop(long)} folds the elapsed delta into the shared
 * total/count under a lock, keeping them consistent when one leaf breakdown is shared across slice
 * threads. Only exercised while profiling.
 */
public final class CryptoNanosMetric extends ProfileMetric {

    private long total = 0L;
    private long count = 0L;

    public CryptoNanosMetric(String name) {
        super(name);
    }

    /** @return the start timestamp; the caller holds it locally and passes it back to {@link #stop(long)}. */
    public long start() {
        return System.nanoTime();
    }

    /** Fold one elapsed sample into the total/count. */
    public synchronized void stop(long startNanos) {
        total += System.nanoTime() - startNanos;
        count++;
    }

    @Override
    public synchronized Map<String, Long> toBreakdownMap() {
        Map<String, Long> m = new LinkedHashMap<>();
        m.put(getName(), total);
        m.put(getName() + "_count", count);
        return m;
    }
}
