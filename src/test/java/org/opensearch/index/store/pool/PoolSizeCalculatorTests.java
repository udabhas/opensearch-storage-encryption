/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;

import java.lang.reflect.Method;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for the two-config GC-managed direct-ByteBuffer pool sizing model:
 * {@code pool = maxDirectMemory * pool_size_percentage}, {@code allocation_limit = pool * (1 + gc_headroom_fraction)}.
 *
 * <p>The pure sizing/validation math is exercised through the package-private
 * {@link PoolSizeCalculator#computeAndValidatePoolSize} so the tests do not depend on the JVM's actual
 * {@code -XX:MaxDirectMemorySize}, which is not set under the test runner (and whose absence
 * {@link PoolSizeCalculator#calculatePoolSize} deliberately rejects).
 */
public class PoolSizeCalculatorTests extends OpenSearchTestCase {

    private static final long MB = 1024L * 1024L;
    private static final long GB = 1024L * MB;

    // ---- selectPercentage: small-machine vs normal threshold ----

    public void testSelectPercentageUsesSmallBelowThreshold() {
        long belowThreshold = PoolSizeCalculator.SMALL_MACHINE_THRESHOLD_BYTES - 1;
        assertThat(PoolSizeCalculator.selectPercentage(belowThreshold, 0.7, 0.5), equalTo(0.5));
    }

    public void testSelectPercentageUsesNormalAtAndAboveThreshold() {
        // At exactly the threshold the normal percentage is used.
        assertThat(PoolSizeCalculator.selectPercentage(PoolSizeCalculator.SMALL_MACHINE_THRESHOLD_BYTES, 0.7, 0.5), equalTo(0.7));
        assertThat(PoolSizeCalculator.selectPercentage(PoolSizeCalculator.SMALL_MACHINE_THRESHOLD_BYTES + 1, 0.7, 0.5), equalTo(0.7));
    }

    public void testSelectPercentageUsesNormalWhenTotalPhysicalUnknown() {
        // totalPhysical <= 0 means detection failed; fall back to the normal percentage.
        assertThat(PoolSizeCalculator.selectPercentage(0L, 0.7, 0.5), equalTo(0.7));
        assertThat(PoolSizeCalculator.selectPercentage(-1L, 0.7, 0.5), equalTo(0.7));
    }

    // ---- computeAndValidatePoolSize: the sizing math + validation ----

    public void testComputeProducesPercentageOfMaxDirect() {
        long maxDirect = 10L * GB;
        long pool = PoolSizeCalculator.computeAndValidatePoolSize(maxDirect, 32L * GB, 8L * GB, 0.7, 0.10);
        assertThat(pool, equalTo((long) (maxDirect * 0.7)));
    }

    public void testComputeEnforcesMinimumPoolSize() {
        // A tiny percentage of a small budget would fall below the 256 MB floor; the floor wins.
        // 256 MB * 1.10 = 281.6 MB <= 1 GB budget, so validation still passes.
        long pool = PoolSizeCalculator.computeAndValidatePoolSize(1L * GB, 32L * GB, 8L * GB, 0.001, 0.10);
        assertThat(pool, equalTo(256L * MB));
    }

    public void testComputeThrowsWhenMaxDirectMemoryNotSet() {
        // maxDirectMemory <= 0 means -XX:MaxDirectMemorySize was not set; must fail fast, not size off heap.
        IllegalStateException e = expectThrows(
            IllegalStateException.class,
            () -> PoolSizeCalculator.computeAndValidatePoolSize(0L, 32L * GB, 8L * GB, 0.7, 0.10)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("MaxDirectMemorySize"));
    }

    public void testComputeThrowsWhenPoolPlusHeadroomExceedsMaxDirect() {
        // pool = 0.95 * maxDirect, headroom 0.10 -> required = 1.045 * maxDirect > maxDirect -> reject.
        IllegalStateException e = expectThrows(
            IllegalStateException.class,
            () -> PoolSizeCalculator.computeAndValidatePoolSize(10L * GB, 32L * GB, 8L * GB, 0.95, 0.10)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("exceeds max direct memory"));
    }

    public void testComputeAllowsPoolPlusHeadroomExactlyAtLimit() {
        // pool = 0.5 * maxDirect, headroom 1.0 -> required = 1.0 * maxDirect == maxDirect -> allowed (not >).
        long maxDirect = 8L * GB;
        long pool = PoolSizeCalculator.computeAndValidatePoolSize(maxDirect, 32L * GB, 8L * GB, 0.5, 1.0);
        assertThat(pool, equalTo(maxDirect / 2));
    }

    // ---- getGcHeadroomFraction ----

    public void testGetGcHeadroomFractionDefault() {
        assertThat(
            PoolSizeCalculator.getGcHeadroomFraction(Settings.EMPTY),
            equalTo(PoolSizeCalculator.NODE_GC_HEADROOM_FRACTION_SETTING.get(Settings.EMPTY))
        );
    }

    public void testGetGcHeadroomFractionCustom() {
        Settings settings = Settings.builder().put(PoolSizeCalculator.NODE_GC_HEADROOM_FRACTION_SETTING.getKey(), 0.25).build();
        assertThat(PoolSizeCalculator.getGcHeadroomFraction(settings), equalTo(0.25));
    }

    // ---- parseSize (renamed from parseMemorySize; now throws on malformed input) ----

    public void testParseSizeUnitsViaReflection() throws Exception {
        Method parseSize = PoolSizeCalculator.class.getDeclaredMethod("parseSize", String.class);
        parseSize.setAccessible(true);

        assertThat((Long) parseSize.invoke(null, "1024"), equalTo(1024L));
        assertThat((Long) parseSize.invoke(null, "1k"), equalTo(1024L));
        assertThat((Long) parseSize.invoke(null, "1K"), equalTo(1024L));
        assertThat((Long) parseSize.invoke(null, "1m"), equalTo(MB));
        assertThat((Long) parseSize.invoke(null, "1M"), equalTo(MB));
        assertThat((Long) parseSize.invoke(null, "1g"), equalTo(GB));
        assertThat((Long) parseSize.invoke(null, "1G"), equalTo(GB));
        assertThat((Long) parseSize.invoke(null, "512m"), equalTo(512L * MB));
    }

    public void testParseSizeThrowsOnMalformedInput() throws Exception {
        Method parseSize = PoolSizeCalculator.class.getDeclaredMethod("parseSize", String.class);
        parseSize.setAccessible(true);

        // parseSize now surfaces malformed input as NumberFormatException (wrapped by reflection)
        // rather than silently returning 0L, so a garbled -XX:MaxDirectMemorySize fails loudly.
        java.lang.reflect.InvocationTargetException ex = expectThrows(
            java.lang.reflect.InvocationTargetException.class,
            () -> parseSize.invoke(null, "invalid")
        );
        assertTrue(ex.getCause() instanceof NumberFormatException);
    }

    // ---- getMaxDirectMemorySize (renamed from getMaxDirectMemory; returns 0 when unset) ----

    public void testGetMaxDirectMemorySizeReturnsZeroWhenUnset() throws Exception {
        // The test runner does not set -XX:MaxDirectMemorySize, so this returns 0 (the sentinel
        // that calculatePoolSize rejects). If a future runner config sets it, this asserts a sane value.
        Method getMaxDirectMemorySize = PoolSizeCalculator.class.getDeclaredMethod("getMaxDirectMemorySize");
        getMaxDirectMemorySize.setAccessible(true);
        long maxDirect = (Long) getMaxDirectMemorySize.invoke(null);
        assertThat("MaxDirectMemorySize sentinel/positive", maxDirect, greaterThan(-1L));
    }

    // ---- end-to-end: calculatePoolSize rejects an unset MaxDirectMemorySize ----

    public void testCalculatePoolSizeThrowsWhenMaxDirectMemoryNotSet() {
        // Under the test JVM, -XX:MaxDirectMemorySize is not set -> getMaxDirectMemorySize() == 0
        // -> calculatePoolSize must throw IllegalStateException rather than sizing off heap.
        // (Guarded so the suite still passes on a runner that DOES set MaxDirectMemorySize.)
        Method m;
        try {
            m = PoolSizeCalculator.class.getDeclaredMethod("getMaxDirectMemorySize");
            m.setAccessible(true);
            long maxDirect = (Long) m.invoke(null);
            if (maxDirect > 0) {
                long pool = PoolSizeCalculator.calculatePoolSize(Settings.EMPTY);
                assertThat(pool, greaterThan(0L));
                return;
            }
        } catch (Exception e) {
            throw new AssertionError("reflection on getMaxDirectMemorySize failed", e);
        }
        expectThrows(IllegalStateException.class, () -> PoolSizeCalculator.calculatePoolSize(Settings.EMPTY));
    }
}
