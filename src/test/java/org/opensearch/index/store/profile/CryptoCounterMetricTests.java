/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import java.util.Map;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for {@link CryptoCounterMetric} — the LongAdder-backed profiler counter that the core
 * sums across slices/leaves. Pins the single-key breakdown output and the add/increment arithmetic.
 */
public class CryptoCounterMetricTests extends OpenSearchTestCase {

    private static final String NAME = "crypto_test_counter";

    public void testStartsAtZeroWithSingleKey() {
        CryptoCounterMetric c = new CryptoCounterMetric(NAME);
        Map<String, Long> m = c.toBreakdownMap();

        assertEquals(1, m.size());
        assertEquals(0L, (long) m.get(NAME));
    }

    public void testIncrement() {
        CryptoCounterMetric c = new CryptoCounterMetric(NAME);
        c.increment();
        c.increment();
        c.increment();

        assertEquals(3L, (long) c.toBreakdownMap().get(NAME));
    }

    public void testAdd() {
        CryptoCounterMetric c = new CryptoCounterMetric(NAME);
        c.add(40L);
        c.add(2L);

        assertEquals(42L, (long) c.toBreakdownMap().get(NAME));
    }

    public void testAddAndIncrementCombine() {
        CryptoCounterMetric c = new CryptoCounterMetric(NAME);
        c.add(10L);
        c.increment();
        c.add(5L);

        assertEquals(16L, (long) c.toBreakdownMap().get(NAME));
    }

    public void testAddZeroAndNegativeAreHonored() {
        CryptoCounterMetric c = new CryptoCounterMetric(NAME);
        c.add(100L);
        c.add(0L);
        c.add(-30L);

        assertEquals(70L, (long) c.toBreakdownMap().get(NAME));
    }

    public void testMetricNameIsPreserved() {
        CryptoCounterMetric c = new CryptoCounterMetric(NAME);
        assertEquals(NAME, c.getName());
    }
}
