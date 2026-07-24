/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.Test;

/**
 * Unit tests for {@link RefCountedByteBuffer} — GC-managed, no ref counting.
 */
public class RefCountedByteBufferTests {

    private static final int BLOCK_SIZE = 8192;

    @Test
    public void testValueReturnsSelf() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        assertSame(rcb, rcb.value());
    }

    @Test
    public void testBufferReturnsBacking() {
        ByteBuffer buf = ByteBuffer.allocateDirect(BLOCK_SIZE);
        RefCountedByteBuffer rcb = new RefCountedByteBuffer(buf, BLOCK_SIZE);
        assertSame(buf, rcb.buffer());
    }

    @Test
    public void testSegmentViewSharesMemory() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.buffer().put(0, (byte) 42);
        assertEquals((byte) 42, rcb.segment().get(java.lang.foreign.ValueLayout.JAVA_BYTE, 0));
    }

    @Test
    public void testLength() {
        RefCountedByteBuffer rcb = new RefCountedByteBuffer(ByteBuffer.allocateDirect(BLOCK_SIZE), 4096);
        assertEquals(4096, rcb.length());
    }

    @Test
    public void testGenerationAlwaysZero() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        assertEquals(0, rcb.getGeneration());
        rcb.close();
        assertEquals(0, rcb.getGeneration());
    }

    // ---- tryPin / close ----

    @Test
    public void testTryPinSucceedsWhenOpen() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        assertTrue(rcb.tryPin());
    }

    @Test
    public void testTryPinAlwaysSucceeds() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.close();
        assertTrue(rcb.tryPin()); // close is no-op, tryPin always true
    }

    @Test
    public void testDecRefIsNoOp() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.decRef();
        assertTrue(rcb.tryPin()); // decRef is no-op
    }

    @Test
    public void testCloseIsNoOp() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.close();
        rcb.close(); // should not throw
        assertTrue(rcb.tryPin());
    }

    // ---- unpin is no-op ----

    @Test
    public void testUnpinDoesNothing() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.unpin(); // should not throw or change state
        assertTrue(rcb.tryPin());
    }

    // ---- data access ----

    @Test
    public void testReadWriteByte() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.buffer().put(100, (byte) 0xAB);
        assertEquals((byte) 0xAB, rcb.buffer().get(100));
    }

    @Test
    public void testReadWriteInt() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.buffer().order(ByteOrder.LITTLE_ENDIAN).putInt(200, 0xDEADBEEF);
        assertEquals(0xDEADBEEF, rcb.buffer().order(ByteOrder.LITTLE_ENDIAN).getInt(200));
    }

    @Test
    public void testReadWriteLong() {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        rcb.buffer().order(ByteOrder.LITTLE_ENDIAN).putLong(300, 0x123456789ABCDEF0L);
        assertEquals(0x123456789ABCDEF0L, rcb.buffer().order(ByteOrder.LITTLE_ENDIAN).getLong(300));
    }

    // ---- concurrent reads ----

    @Test
    public void testAbsoluteReadsAreThreadSafe() throws Exception {
        RefCountedByteBuffer rcb = create(BLOCK_SIZE);
        ByteBuffer buf = rcb.buffer().order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < BLOCK_SIZE; i += 8) {
            buf.putLong(i, i);
        }

        Thread[] threads = new Thread[8];
        boolean[] results = new boolean[8];
        for (int t = 0; t < threads.length; t++) {
            final int idx = t;
            threads[t] = new Thread(() -> {
                boolean ok = true;
                for (int i = 0; i < BLOCK_SIZE; i += 8) {
                    if (rcb.buffer().order(ByteOrder.LITTLE_ENDIAN).getLong(i) != i) {
                        ok = false;
                        break;
                    }
                }
                results[idx] = ok;
            });
            threads[t].start();
        }
        for (Thread thread : threads)
            thread.join();
        for (boolean result : results)
            assertTrue(result);
    }

    private static RefCountedByteBuffer create(int size) {
        return new RefCountedByteBuffer(ByteBuffer.allocateDirect(size), size);
    }
}
