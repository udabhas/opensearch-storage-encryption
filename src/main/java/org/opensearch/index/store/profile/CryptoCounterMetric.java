/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.LongAdder;

import org.opensearch.search.profile.ProfileMetric;

/**
 * A {@link ProfileMetric} backed by a {@link LongAdder}. Because it is NOT a
 * {@link org.opensearch.search.profile.Timer}, the core profiler treats it as a non-timing metric
 * and SUMS it across slices/leaves — exactly the semantics we want for churn counters (hits, misses,
 * bytes, blocks). Lock-free, so a stray concurrent increment is safe.
 */
public final class CryptoCounterMetric extends ProfileMetric {

    private final LongAdder value = new LongAdder();

    public CryptoCounterMetric(String name) {
        super(name);
    }

    /** Add {@code n} to the counter. */
    public void add(long n) {
        value.add(n);
    }

    /** Increment by one. */
    public void increment() {
        value.increment();
    }

    @Override
    public Map<String, Long> toBreakdownMap() {
        return Collections.singletonMap(getName(), value.sum());
    }
}
