/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import java.util.Map;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for {@link CryptoHistogramMetric} — the dependency-free, log-bucketed distribution used
 * by the storage-encryption query profiler. Pins the exact aggregate keys (count/total/min/max), the
 * empty-state contract, the ~10% percentile accuracy, and the bucket-clamping guarantees.
 */
public class CryptoHistogramMetricTests extends OpenSearchTestCase {

    private static final String NAME = "crypto_test_dist";

    public void testEmptyEmitsZeroesAndDoesNotReportStaleMin() {
        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        Map<String, Long> m = h.toBreakdownMap();

        assertEquals(0L, (long) m.get(NAME + "_count"));
        assertEquals(0L, (long) m.get(NAME + "_total"));
        // min must be reported as 0 when empty, not Long.MAX_VALUE.
        assertEquals(0L, (long) m.get(NAME + "_min"));
        assertEquals(0L, (long) m.get(NAME + "_max"));
        assertEquals(0L, (long) m.get(NAME + "_p50"));
        assertEquals(0L, (long) m.get(NAME + "_p90"));
        assertEquals(0L, (long) m.get(NAME + "_p99"));
    }

    public void testEmitsBareNameKeyForConcurrentSearchReduce() {
        // The concurrent-segment-search reduce path looks up map.get(metricName) per slice and unboxes
        // to a primitive long, so a key equal to the bare metric name must always be present and hold
        // the running total (both empty and populated).
        CryptoHistogramMetric empty = new CryptoHistogramMetric(NAME);
        assertTrue("bare name key must exist when empty", empty.toBreakdownMap().containsKey(NAME));
        assertEquals(0L, (long) empty.toBreakdownMap().get(NAME));

        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        h.record(100L);
        h.record(250L);
        assertEquals(350L, (long) h.toBreakdownMap().get(NAME));
        assertEquals((long) h.toBreakdownMap().get(NAME + "_total"), (long) h.toBreakdownMap().get(NAME));
    }

    public void testCountTotalMinMaxAreExact() {
        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        long[] samples = { 100L, 5L, 4000L, 250L, 12L };
        long expectedTotal = 0L, expectedMin = Long.MAX_VALUE, expectedMax = 0L;
        for (long s : samples) {
            h.record(s);
            expectedTotal += s;
            expectedMin = Math.min(expectedMin, s);
            expectedMax = Math.max(expectedMax, s);
        }
        Map<String, Long> m = h.toBreakdownMap();

        assertEquals(samples.length, (long) m.get(NAME + "_count"));
        assertEquals(expectedTotal, (long) m.get(NAME + "_total"));
        // min and max are tracked exactly, not bucketed.
        assertEquals(expectedMin, (long) m.get(NAME + "_min"));
        assertEquals(expectedMax, (long) m.get(NAME + "_max"));
    }

    public void testPercentilesWithinTenPercentOfTruth() {
        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        long value = 1_000_000L;
        for (int i = 0; i < 1000; i++) {
            h.record(value);
        }
        Map<String, Long> m = h.toBreakdownMap();

        for (String key : new String[] { "_p50", "_p90", "_p99" }) {
            long p = m.get(NAME + key);
            assertTrue(key + "=" + p + " should be >= 0.9*value", p >= (long) (value * 0.90));
            assertTrue(key + "=" + p + " should be <= value (clamped to max)", p <= value);
        }
    }

    public void testPercentilesAreMonotonicAcrossASpread() {
        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        for (int i = 1; i <= 1000; i++) {
            h.record(i);
        }
        Map<String, Long> m = h.toBreakdownMap();
        long p50 = m.get(NAME + "_p50");
        long p90 = m.get(NAME + "_p90");
        long p99 = m.get(NAME + "_p99");

        assertTrue("p50 <= p90", p50 <= p90);
        assertTrue("p90 <= p99", p90 <= p99);
        assertTrue(p50 >= (long) m.get(NAME + "_min"));
        assertTrue(p99 <= (long) m.get(NAME + "_max"));
    }

    public void testNonPositiveSampleCountsTowardCountAndMin() {
        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        h.record(0L);
        h.record(-5L);
        h.record(10L);
        Map<String, Long> m = h.toBreakdownMap();

        assertEquals(3L, (long) m.get(NAME + "_count"));
        assertEquals(5L, (long) m.get(NAME + "_total"));  // 0 + (-5) + 10
        assertEquals(-5L, (long) m.get(NAME + "_min"));
        assertEquals(10L, (long) m.get(NAME + "_max"));
    }

    public void testVeryLargeValueClampsIntoTopBucketWithoutOverflow() {
        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        long huge = Long.MAX_VALUE / 2;
        h.record(huge);
        Map<String, Long> m = h.toBreakdownMap();

        assertEquals(1L, (long) m.get(NAME + "_count"));
        assertEquals(huge, (long) m.get(NAME + "_max"));
        assertEquals(huge, (long) m.get(NAME + "_p50"));
    }

    public void testMetricNameIsPreserved() {
        CryptoHistogramMetric h = new CryptoHistogramMetric(NAME);
        assertEquals(NAME, h.getName());
    }
}
