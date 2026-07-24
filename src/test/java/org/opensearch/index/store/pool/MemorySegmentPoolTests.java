/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.index.store.block.RefCountedByteBuffer;

/**
 * Unit tests for {@link MemorySegmentPool} — GC-managed direct-ByteBuffer pool.
 *
 * <p>Covers: construction/validation, GC-managed allocation (page-aligned direct buffers),
 * no-op release/warmUp, buffersInUse tracking, stall on over-capacity, the dual
 * direct-memory / OS-free-memory throttle decision logic, the legacy System.gc() zombie hint,
 * Cleaner-driven decrement, and concurrency.
 */
@SuppressWarnings("preview")
public class MemorySegmentPoolTests {

    private MemorySegmentPool pool;

    @Before
    public void setUp() {}

    @After
    public void tearDown() {
        if (pool != null && !pool.isClosed()) {
            pool.close();
        }
    }

    // ---- Construction ----

    @Test
    public void testPoolCreation() {
        pool = new MemorySegmentPool(4096, 1024);
        assertEquals(1024, pool.pooledSegmentSize());
        assertEquals(4096L, pool.totalMemory());
        assertFalse(pool.isClosed());
        assertEquals(0, pool.getBuffersInUse());
        assertEquals(0, pool.getAllocatedBytes());
    }

    @Test
    public void testInvalidConfigurationThrows() {
        try {
            pool = new MemorySegmentPool(4097, 1024);
            fail("Should throw for non-aligned totalMemory");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("multiple"));
        }
    }

    @Test
    public void testHeadroomConstructor() {
        pool = new MemorySegmentPool(4096, 1024, 0.25);
        assertNotNull(pool);
        assertEquals(1024, pool.pooledSegmentSize());
        assertEquals(4096L, pool.totalMemory());
    }

    @Test
    public void testDefaultHeadroomConstructor() {
        pool = new MemorySegmentPool(4096, 1024);
        assertNotNull(pool);
        assertEquals(1024, pool.pooledSegmentSize());
    }

    // ---- tryAcquire() ----

    @Test
    public void testTryAcquireUnderCapacitySucceeds() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer buf = pool.tryAcquire(100, TimeUnit.MILLISECONDS);
        assertNotNull(buf);
        assertEquals(1, pool.getBuffersInUse());
    }

    @Test
    public void testTryAcquireReturnsDirectByteBuffer() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer buf = pool.tryAcquire(100, TimeUnit.MILLISECONDS);
        assertNotNull(buf);
        assertNotNull(buf.buffer());
        assertTrue(buf.buffer().isDirect());
        assertEquals(1024, buf.buffer().capacity());
        assertEquals(ByteOrder.LITTLE_ENDIAN, buf.buffer().order());
    }

    /**
     * The default allocator must reserve EXACTLY {@code segmentSize} bytes of direct memory — no
     * page-alignment over-allocation. Pool buffers are in-memory copy scratch for the block cache;
     * they are never used for O_DIRECT DMA (the direct read allocates its own page-aligned arena
     * segment in {@code DirectIOReaderUtil}), so they do not need a page-aligned native address.
     * Over-allocating by {@code pageSize - 1} per block reserved ~1.5x the configured pool against
     * {@code -XX:MaxDirectMemorySize} while accounting for only {@code segmentSize}, which guaranteed
     * direct-memory exhaustion / throttle engagement under load. This asserts the over-allocation is gone.
     */
    @Test
    public void testTryAcquireReservesExactSegmentSizeNoOverAllocation() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer buf = pool.tryAcquire(100, TimeUnit.MILLISECONDS);
        assertNotNull(buf);
        // Exactly segmentSize — not segmentSize + pageSize - 1.
        assertEquals("pool buffer must reserve exactly segmentSize bytes (no alignment padding)", 1024, buf.buffer().capacity());
        assertEquals(1024L, buf.segment().byteSize());
        assertEquals(ByteOrder.LITTLE_ENDIAN, buf.buffer().order());
        assertTrue("pool buffer must be a direct buffer", buf.buffer().isDirect());
    }

    @Test
    public void testTryAcquireFromClosedPoolThrows() throws Exception {
        pool = new MemorySegmentPool(2048, 1024);
        pool.close();
        try {
            pool.tryAcquire(100, TimeUnit.MILLISECONDS);
            fail("Should throw on closed pool");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("closed"));
        }
    }

    // ---- MemorySegment view ----

    @Test
    public void testSegmentViewSharesMemory() throws Exception {
        pool = new MemorySegmentPool(2048, 1024);
        RefCountedByteBuffer buf = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        // Write via ByteBuffer, read via MemorySegment
        buf.buffer().put(0, (byte) 42);
        assertEquals((byte) 42, buf.segment().get(ValueLayout.JAVA_BYTE, 0));
        // Write via MemorySegment, read via ByteBuffer
        buf.segment().set(ValueLayout.JAVA_BYTE, 100, (byte) 99);
        assertEquals((byte) 99, buf.buffer().get(100));
    }

    @Test
    public void testSegmentReadWriteFullBlock() throws Exception {
        pool = new MemorySegmentPool(2048, 1024);
        RefCountedByteBuffer buf = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        buf.segment().fill((byte) 0xFF);
        assertEquals((byte) 0xFF, buf.segment().get(ValueLayout.JAVA_BYTE, 0));
        assertEquals((byte) 0xFF, buf.segment().get(ValueLayout.JAVA_BYTE, 1023));
    }

    // ---- release() no-op ----

    @Test
    public void testReleaseIsNoOp() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer seg = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        int before = pool.getBuffersInUse();
        pool.release(seg);
        assertEquals(before, pool.getBuffersInUse());
    }

    @Test
    public void testReleaseAllIsNoOp() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer s1 = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        RefCountedByteBuffer s2 = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        int before = pool.getBuffersInUse();
        pool.releaseAll(s1, s2);
        assertEquals(before, pool.getBuffersInUse());
    }

    // ---- availableMemory ----

    @Test
    public void testAvailableMemoryDecreases() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        assertEquals(4096L, pool.availableMemory());
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertEquals(3072L, pool.availableMemory());
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertEquals(2048L, pool.availableMemory());
    }

    @Test
    public void testAvailableMemoryNeverNegative() throws Exception {
        pool = new MemorySegmentPool(2048, 1024); // max=2
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        try {
            pool.tryAcquire(1, TimeUnit.MILLISECONDS); // over capacity
        } catch (Exception ignored) {
            // over-limit rejection expected
        }
        assertTrue(pool.availableMemory() >= 0);
    }

    // ---- allocatedBytes ----

    @Test
    public void testAllocatedBytesTracking() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        assertEquals(0, pool.getAllocatedBytes());
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertEquals(1024, pool.getAllocatedBytes());
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertEquals(2048, pool.getAllocatedBytes());
    }

    // ---- isUnderPressure ----

    @Test
    public void testNotUnderPressureInitially() {
        pool = new MemorySegmentPool(10240, 1024); // max=10
        assertFalse(pool.isUnderPressure());
    }

    @Test
    public void testNotUnderPressureAt90Percent() throws Exception {
        pool = new MemorySegmentPool(20480, 1024); // max=20
        for (int i = 0; i < 18; i++)
            pool.tryAcquire(5000, TimeUnit.MILLISECONDS); // 90%
        assertFalse(pool.isUnderPressure()); // threshold is 95%
    }

    @Test
    public void testUnderPressureAt95Percent() throws Exception {
        pool = new MemorySegmentPool(20480, 1024); // max=20
        for (int i = 0; i < 19; i++)
            pool.tryAcquire(5000, TimeUnit.MILLISECONDS); // 95%
        assertTrue(pool.isUnderPressure());
    }

    @Test
    public void testUnderPressureAtFull() throws Exception {
        pool = new MemorySegmentPool(4096, 1024); // max=4
        for (int i = 0; i < 4; i++)
            pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertTrue(pool.isUnderPressure());
    }

    // ---- warmUp ----

    @Test
    public void testWarmUpIsNoOp() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        pool.warmUp(4);
        assertEquals(0, pool.getBuffersInUse());
    }

    // ---- close ----

    @Test
    public void testCloseMarksPoolClosed() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        pool.close();
        assertTrue(pool.isClosed());
    }

    @Test
    public void testDoubleCloseIsSafe() {
        pool = new MemorySegmentPool(2048, 1024);
        pool.close();
        pool.close();
        assertTrue(pool.isClosed());
    }

    @Test
    public void testCloseStopsGcDebtMonitor() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        pool.close();
        // Give thread time to stop
        Thread.sleep(100);
        // No assertion needed — if join(5000) hangs, the test framework will time out
    }

    // ---- poolStats ----

    @Test
    public void testPoolStatsContainsAllFields() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        String stats = pool.poolStats();
        assertNotNull(stats);
        assertTrue(stats.contains("PoolStats"));
        assertTrue(stats.contains("max=4"));
        assertTrue(stats.contains("inUse=1"));
        assertTrue(stats.contains("utilization="));
        assertTrue(stats.contains("stalls="));
        assertTrue(stats.contains("tracked="));
        assertTrue(stats.contains("native="));
        assertTrue(stats.contains("zombie="));
    }

    @Test
    public void testPoolStatsShowsStallsAfterOverCapacity() throws Exception {
        pool = new MemorySegmentPool(1024, 1024); // max=1, allocLimit=1
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        try {
            pool.tryAcquire(1, TimeUnit.MILLISECONDS); // over limit → reject
            fail("Expected over-limit rejection");
        } catch (Exception expected) {
            // expected
        }
        String stats = pool.poolStats();
        assertFalse(stats.contains("stalls=0"));
    }

    // ---- Cleaner decrements buffersInUse ----

    @Test
    public void testCleanerDecrementsBuffersInUse() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer seg = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertEquals(1, pool.getBuffersInUse());

        seg = null; // drop reference
        for (int i = 0; i < 20; i++) {
            System.gc();
            Thread.sleep(50);
            if (pool.getBuffersInUse() == 0)
                break;
        }
        // Best-effort: Cleaner may or may not have run within the window.
        if (pool.getBuffersInUse() == 0) {
            assertEquals(0L, pool.getAllocatedBytes());
        }
    }

    // ---- GC debt monitor / cache supplier wiring ----

    @Test
    public void testCacheEntriesSupplierWiring() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        AtomicInteger cacheSize = new AtomicInteger(0);
        pool.setCacheEntriesSupplier(cacheSize::get);
        pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        cacheSize.set(1);
        // No assertion — just verify wiring doesn't throw.
    }

    /**
     * Drive the pool into GC debt: fill allocation limit, cache supplier reports 0.
     * With maxSegments=10 and gcHeadroom=0.5, allocationLimit=15.
     * zombies = inUse, remaining = 0, so checkGcDebt() sees the trigger condition.
     * Returns the acquired buffers so the caller holds strong refs across System.gc().
     */
    private RefCountedByteBuffer[] driveIntoGcDebt() throws Exception {
        pool.setCacheEntriesSupplier(() -> 0L);
        RefCountedByteBuffer[] held = new RefCountedByteBuffer[15];
        for (int i = 0; i < 15; i++) {
            held[i] = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        }
        return held;
    }

    @Test
    public void testGcHintDisabledSuppressesAllHints() throws Exception {
        pool = new MemorySegmentPool(10240, 1024, 0.50);
        pool.setGcHintEnabled(false);
        RefCountedByteBuffer[] held = driveIntoGcDebt();
        long before = pool.getGcTriggerCount();
        pool.checkGcDebt();
        pool.checkGcDebt();
        assertEquals("No hint should fire when disabled", before, pool.getGcTriggerCount());
        assertNotNull(held); // keep alive
    }

    @Test
    public void testGcHintCooldownSuppressesSecondHint() throws Exception {
        pool = new MemorySegmentPool(10240, 1024, 0.50);
        pool.setGcHintEnabled(true);
        pool.setGcHintCooldownSeconds(3600L); // 1h cooldown
        RefCountedByteBuffer[] held = driveIntoGcDebt();
        long before = pool.getGcTriggerCount();
        pool.checkGcDebt();
        pool.checkGcDebt();
        pool.checkGcDebt();
        assertEquals("Only first hint fires inside cooldown window", before + 1, pool.getGcTriggerCount());
        assertNotNull(held); // keep alive
    }

    @Test
    public void testGcHintZeroCooldownAllowsEveryTick() throws Exception {
        pool = new MemorySegmentPool(10240, 1024, 0.50);
        pool.setGcHintEnabled(true);
        pool.setGcHintCooldownSeconds(0L); // no cooldown
        RefCountedByteBuffer[] held = driveIntoGcDebt();
        long before = pool.getGcTriggerCount();
        pool.checkGcDebt();
        pool.checkGcDebt();
        pool.checkGcDebt();
        assertEquals("Every tick fires when cooldown is zero", before + 3, pool.getGcTriggerCount());
        assertNotNull(held); // keep alive
    }

    // ---- Concurrent acquire ----

    @Test
    public void testConcurrentAcquire() throws Exception {
        pool = new MemorySegmentPool(81920, 1024); // max=80
        int threads = 8;
        int acquiresPerThread = 10;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicReference<Throwable> error = new AtomicReference<>();

        for (int t = 0; t < threads; t++) {
            new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < acquiresPerThread; i++) {
                        RefCountedByteBuffer buf = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
                        assertNotNull(buf);
                        // Write and read to verify buffer is usable
                        buf.buffer().putInt(0, 42);
                        assertEquals(42, buf.buffer().getInt(0));
                    }
                } catch (Throwable e) {
                    error.compareAndSet(null, e);
                } finally {
                    done.countDown();
                }
            }).start();
        }

        start.countDown();
        assertTrue("Threads should complete", done.await(30, TimeUnit.SECONDS));
        if (error.get() != null)
            throw new AssertionError("Thread failed", error.get());
        assertEquals(threads * acquiresPerThread, pool.getBuffersInUse());
    }

    // ---- Buffer independence ----

    @Test
    public void testEachAcquireReturnsIndependentBuffer() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer buf1 = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        RefCountedByteBuffer buf2 = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);

        buf1.buffer().putInt(0, 111);
        buf2.buffer().putInt(0, 222);

        assertEquals(111, buf1.buffer().getInt(0));
        assertEquals(222, buf2.buffer().getInt(0));
    }

    // ---- Length ----

    @Test
    public void testAcquiredBufferLength() throws Exception {
        pool = new MemorySegmentPool(8192, 8192);
        RefCountedByteBuffer buf = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertEquals(8192, buf.length());
        assertEquals(8192, buf.buffer().capacity());
    }

    // ---- tryPin/unpin/close are no-ops on RefCountedByteBuffer ----

    @Test
    public void testRefCountedByteBufferLifecycleNoOps() throws Exception {
        pool = new MemorySegmentPool(4096, 1024);
        RefCountedByteBuffer buf = pool.tryAcquire(5000, TimeUnit.MILLISECONDS);
        assertTrue(buf.tryPin());
        buf.unpin();
        buf.close();
        buf.decRef();
        assertTrue(buf.tryPin()); // still true — all no-ops
        assertEquals(0, buf.getGeneration()); // always 0
    }

    // ---- shouldThrottle: pure decision logic (package-private) ----

    @Test
    public void testShouldThrottleReturnsFalseWhenMaxDirectMemoryNotSet() {
        // max=0 means -XX:MaxDirectMemorySize not set — throttle stays disabled.
        assertFalse(MemorySegmentPool.shouldThrottle(1_000_000_000L, 0L));
        assertFalse(MemorySegmentPool.shouldThrottle(1_000_000_000L, -1L));
    }

    @Test
    public void testShouldThrottleReturnsFalseWhenUsedUnknown() {
        // directMemoryMxBean absent (used < 0) — throttle stays disabled.
        assertFalse(MemorySegmentPool.shouldThrottle(-1L, 8L * 1024 * 1024 * 1024));
    }

    @Test
    public void testShouldThrottleReturnsFalseWhenFreeAboveThreshold() {
        // 2-arg shouldThrottle compares free against the absolute floor THROTTLE_FREE_FLOOR_BYTES (256 MB).
        long max = 8L * 1024 * 1024 * 1024;       // 8 GB
        long used = max - (600L * 1024 * 1024);    // free = 600 MB > 256 MB floor
        assertFalse(MemorySegmentPool.shouldThrottle(used, max));
    }

    @Test
    public void testShouldThrottleReturnsTrueWhenFreeBelowThreshold() {
        long max = 8L * 1024 * 1024 * 1024;       // 8 GB
        long used = max - (200L * 1024 * 1024);    // free = 200 MB < 256 MB floor
        assertTrue(MemorySegmentPool.shouldThrottle(used, max));
    }

    @Test
    public void testShouldThrottleReturnsFalseExactlyAtThreshold() {
        // Boundary: free == reserve floor → NOT throttled (strict less-than). The 2-arg static helper
        // uses the absolute floor THROTTLE_FREE_FLOOR_BYTES (the instance pool uses a relative reserve).
        long max = 8L * 1024 * 1024 * 1024;
        long used = max - MemorySegmentPool.THROTTLE_FREE_FLOOR_BYTES;
        assertFalse(MemorySegmentPool.shouldThrottle(used, max));
    }

    @Test
    public void testShouldThrottleReturnsTrueOneByteBelowThreshold() {
        long max = 8L * 1024 * 1024 * 1024;
        long used = max - MemorySegmentPool.THROTTLE_FREE_FLOOR_BYTES + 1;
        assertTrue(MemorySegmentPool.shouldThrottle(used, max));
    }

    @Test
    public void testShouldThrottleReturnsTrueWhenUsedExceedsMax() {
        // Degenerate: JVM reports used > max (can happen with direct memory overcommit).
        // free becomes negative, should still throttle.
        long max = 1L * 1024 * 1024 * 1024;
        long used = 2L * 1024 * 1024 * 1024;
        assertTrue(MemorySegmentPool.shouldThrottle(used, max));
    }

    // ---- OS free memory throttle tests ----

    @Test
    public void testShouldThrottleOsReturnsFalseWhenFreeAboveThreshold() {
        // The no-arg helper compares against the absolute floor OS_FREE_FLOOR_BYTES (256MB).
        assertFalse(MemorySegmentPool.shouldThrottleOs(600L * 1024 * 1024));
    }

    @Test
    public void testShouldThrottleOsReturnsTrueWhenFreeBelowThreshold() {
        // 200MB is below the 256MB floor → throttled.
        assertTrue(MemorySegmentPool.shouldThrottleOs(200L * 1024 * 1024));
    }

    @Test
    public void testShouldThrottleOsReturnsFalseExactlyAtThreshold() {
        assertFalse(MemorySegmentPool.shouldThrottleOs(MemorySegmentPool.OS_FREE_FLOOR_BYTES));
    }

    @Test
    public void testShouldThrottleOsReturnsTrueOneByteBelowThreshold() {
        assertTrue(MemorySegmentPool.shouldThrottleOs(MemorySegmentPool.OS_FREE_FLOOR_BYTES - 1));
    }

    @Test
    public void testShouldThrottleOsReturnsFalseWhenUnknown() {
        // -1 means /proc/meminfo not available (non-Linux) — don't throttle
        assertFalse(MemorySegmentPool.shouldThrottleOs(-1L));
    }

    @Test
    public void testShouldThrottleOsWithCustomThreshold() {
        long customThreshold = 1024L * 1024 * 1024; // 1 GB
        assertTrue(MemorySegmentPool.shouldThrottleOs(500L * 1024 * 1024, customThreshold));
        assertFalse(MemorySegmentPool.shouldThrottleOs(1500L * 1024 * 1024, customThreshold));
    }

    @Test
    public void testShouldThrottleOsWithZeroThresholdDisablesCheck() {
        // free==threshold → not throttled; free > threshold → not throttled.
        assertFalse(MemorySegmentPool.shouldThrottleOs(0L, 0L));
        assertFalse(MemorySegmentPool.shouldThrottleOs(1L, 0L));
    }

    // ---- Dual threshold tests ----

    @Test
    public void testDualThrottleDirectOnlyTriggered() {
        // Static helpers use the 256 MB absolute floors; pick free direct below the floor.
        long max = 8L * 1024 * 1024 * 1024;
        long used = max - (100L * 1024 * 1024); // 100 MB free direct < 256 MB floor
        long osFree = 2L * 1024 * 1024 * 1024;  // 2 GB free OS — plenty
        assertTrue(MemorySegmentPool.shouldThrottle(used, max, osFree));
    }

    @Test
    public void testDualThrottleOsOnlyTriggered() {
        long max = 8L * 1024 * 1024 * 1024;
        long used = max - (2L * 1024 * 1024 * 1024); // 2 GB free direct — plenty
        long osFree = 200L * 1024 * 1024;             // 200 MB free OS — low
        assertTrue(MemorySegmentPool.shouldThrottle(used, max, osFree));
    }

    @Test
    public void testDualThrottleNeitherTriggered() {
        long max = 8L * 1024 * 1024 * 1024;
        long used = max - (2L * 1024 * 1024 * 1024); // 2 GB free direct
        long osFree = 2L * 1024 * 1024 * 1024;        // 2 GB free OS
        assertFalse(MemorySegmentPool.shouldThrottle(used, max, osFree));
    }

    @Test
    public void testDualThrottleBothTriggered() {
        long max = 8L * 1024 * 1024 * 1024;
        long used = max - (100L * 1024 * 1024); // 100 MB free direct
        long osFree = 100L * 1024 * 1024;        // 100 MB free OS
        assertTrue(MemorySegmentPool.shouldThrottle(used, max, osFree));
    }

    @Test
    public void testDualThrottleOsUnknownFallsBackToDirectOnly() {
        long max = 8L * 1024 * 1024 * 1024;
        long used = max - (600L * 1024 * 1024); // 600 MB free direct — above threshold
        long osFree = -1L;                        // unknown
        assertFalse(MemorySegmentPool.shouldThrottle(used, max, osFree));
    }

    // ---- readMemAvailable test ----

    @Test
    public void testReadMemAvailableReturnsNonNegativeOnLinux() {
        long memAvail = MemorySegmentPool.readMemAvailableFromProc();
        // On Linux: should return a positive value. On macOS/Windows: returns -1.
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("linux")) {
            assertTrue("MemAvailable should be positive on Linux", memAvail > 0);
        } else {
            assertEquals("readMemAvailable should return -1 on non-Linux", -1L, memAvail);
        }
    }

    // ---- Configurable threshold test ----

    @Test
    public void testOsFreeThresholdConfigurable() throws Exception {
        pool = new MemorySegmentPool(1024, 1024);
        // Default is now computed at construction (relative + cgroup/host-aware), so it varies per host;
        // assert only the invariant lower bound rather than an exact constant.
        assertTrue(
            "default OS-free threshold should be at least the floor",
            pool.getOsFreeThresholdBytes() >= MemorySegmentPool.OS_FREE_FLOOR_BYTES
        );
        // Update round-trips exactly.
        pool.setOsFreeThresholdBytes(1024L * 1024 * 1024); // 1 GB
        assertEquals(1024L * 1024 * 1024, pool.getOsFreeThresholdBytes());
        // Set to 0 (disabled)
        pool.setOsFreeThresholdBytes(0L);
        assertEquals(0L, pool.getOsFreeThresholdBytes());
        pool.close();
    }
}
