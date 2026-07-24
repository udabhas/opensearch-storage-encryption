/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for {@link RadixBlockTable}: single-threaded map semantics (put/get/remove/clear,
 * directory growth, inner-array reclamation) plus cross-thread visibility smoke tests for
 * the acquire/release slot and directory accesses that L1 invalidation correctness relies on
 * (an eviction's {@code remove} null-out and a {@code clear()} swap must become visible to a
 * concurrent lock-free reader).
 */
public class RadixBlockTableTests extends OpenSearchTestCase {

    public void testPutGetRoundTrip() {
        RadixBlockTable<String> table = new RadixBlockTable<>();
        assertNull(table.get(0));
        table.put(0, "a");
        table.put(1023, "b");
        table.put(1024, "c"); // second inner page
        assertEquals("a", table.get(0));
        assertEquals("b", table.get(1023));
        assertEquals("c", table.get(1024));
        assertNull(table.get(2));
    }

    public void testOverwrite() {
        RadixBlockTable<String> table = new RadixBlockTable<>();
        table.put(7, "old");
        table.put(7, "new");
        assertEquals("new", table.get(7));
    }

    public void testRemoveReturnsPreviousAndClearsSlot() {
        RadixBlockTable<String> table = new RadixBlockTable<>();
        table.put(5, "x");
        assertEquals("x", table.remove(5));
        assertNull(table.get(5));
        assertNull(table.remove(5));
        // Removing from a never-populated page is a no-op.
        assertNull(table.remove(50_000_000L));
    }

    public void testInnerArrayReclaimedWhenEmpty() {
        RadixBlockTable<String> table = new RadixBlockTable<>();
        table.put(0, "a");
        table.put(1, "b");
        assertTrue(table.isInnerAllocated(0));
        table.remove(0);
        assertTrue(table.isInnerAllocated(0)); // still holds "b"
        table.remove(1);
        assertFalse(table.isInnerAllocated(0)); // fully empty -> reclaimed
        // Table remains usable after reclamation.
        table.put(1, "c");
        assertEquals("c", table.get(1));
    }

    public void testDirectoryGrowsBeyondDefault() {
        RadixBlockTable<String> table = new RadixBlockTable<>();
        int defaultLength = table.directoryLength();
        long farBlockId = (long) (defaultLength + 3) << RadixBlockTable.PAGE_SHIFT;
        assertNull(table.get(farBlockId)); // out-of-range read is a miss, not an error
        table.put(farBlockId, "far");
        assertTrue(table.directoryLength() > defaultLength);
        assertEquals("far", table.get(farBlockId));
    }

    public void testClearEmptiesAllEntries() {
        RadixBlockTable<String> table = new RadixBlockTable<>();
        table.put(0, "a");
        table.put(5000, "b");
        int lengthBefore = table.directoryLength();
        table.clear();
        assertNull(table.get(0));
        assertNull(table.get(5000));
        assertEquals(lengthBefore, table.directoryLength());
        assertEquals(0, table.allocatedInnerCount());
    }

    /**
     * Cross-thread visibility of the L1 invalidation primitive: a reader spinning on
     * {@code get(blockId)} must observe the eviction thread's {@code remove} null-out.
     * With plain (non-ordered) slot access this had no happens-before edge (only
     * best-effort hardware coherence); with the release store / acquire load pairing it
     * is guaranteed. A bounded spin keeps the test deterministic-in-practice either way,
     * while documenting the contract this class must uphold.
     */
    public void testRemoveVisibleToConcurrentReader() throws Exception {
        final RadixBlockTable<String> table = new RadixBlockTable<>();
        table.put(42, "live");

        final CountDownLatch readerSeesValue = new CountDownLatch(1);
        final AtomicBoolean sawNull = new AtomicBoolean(false);
        Thread reader = new Thread(() -> {
            // First confirm the published value is visible, then spin until the removal is.
            while (table.get(42) == null) {
                Thread.onSpinWait();
            }
            readerSeesValue.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (System.nanoTime() < deadline) {
                if (table.get(42) == null) {
                    sawNull.set(true);
                    return;
                }
            }
        });
        reader.start();
        assertTrue("reader never observed the initial put", readerSeesValue.await(10, TimeUnit.SECONDS));

        table.remove(42); // the eviction-listener path

        reader.join(TimeUnit.SECONDS.toMillis(15));
        assertFalse("reader thread did not terminate", reader.isAlive());
        assertTrue("reader never observed the eviction null-out", sawNull.get());
    }

    /** Same contract for {@code clear()} — the delete/rename {@code clearFile} invalidation path. */
    public void testClearVisibleToConcurrentReader() throws Exception {
        final RadixBlockTable<String> table = new RadixBlockTable<>();
        table.put(7, "live");

        final CountDownLatch readerSeesValue = new CountDownLatch(1);
        final AtomicBoolean sawEmpty = new AtomicBoolean(false);
        Thread reader = new Thread(() -> {
            while (table.get(7) == null) {
                Thread.onSpinWait();
            }
            readerSeesValue.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (System.nanoTime() < deadline) {
                if (table.get(7) == null) {
                    sawEmpty.set(true);
                    return;
                }
            }
        });
        reader.start();
        assertTrue("reader never observed the initial put", readerSeesValue.await(10, TimeUnit.SECONDS));

        table.clear();

        reader.join(TimeUnit.SECONDS.toMillis(15));
        assertFalse("reader thread did not terminate", reader.isAlive());
        assertTrue("reader never observed clear()", sawEmpty.get());
    }

    /** Concurrent put/remove/get stress across pages — asserts no exceptions and coherent end state. */
    public void testConcurrentMixedOperationsStress() throws Exception {
        final RadixBlockTable<Integer> table = new RadixBlockTable<>();
        final int threads = 4;
        final int opsPerThread = 20_000;
        final CountDownLatch start = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threads);
        final AtomicBoolean failed = new AtomicBoolean(false);

        for (int t = 0; t < threads; t++) {
            final int seed = t;
            new Thread(() -> {
                try {
                    start.await();
                    java.util.Random random = new java.util.Random(seed);
                    for (int i = 0; i < opsPerThread; i++) {
                        long blockId = random.nextInt(4096);
                        switch (random.nextInt(3)) {
                            case 0 -> table.put(blockId, seed);
                            case 1 -> table.remove(blockId);
                            default -> table.get(blockId);
                        }
                    }
                } catch (Throwable e) {
                    failed.set(true);
                } finally {
                    done.countDown();
                }
            }).start();
        }
        start.countDown();
        assertTrue("stress threads did not finish", done.await(60, TimeUnit.SECONDS));
        assertFalse("stress thread threw", failed.get());

        // Post-stress: the table must still behave as a coherent map.
        table.clear();
        table.put(1, 99);
        assertEquals(Integer.valueOf(99), table.get(1));
    }
}
