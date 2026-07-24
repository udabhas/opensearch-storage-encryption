/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * A two-level radix table mapping blockIds to values of type {@code V}.
 * Designed as a per-file L1 lookup cache, but generic enough for any
 * blockId-to-value mapping.
 *
 * <h2>Structure</h2>
 * <pre>
 *   outer index = blockId &gt;&gt;&gt; PAGE_SHIFT   (which group of 1024)
 *   inner slot  = blockId &amp; PAGE_MASK     (position within group)
 * </pre>
 *
 * The outer level defaults to {@value #DEFAULT_OUTER_SLOTS} entries (2 KB),
 * covering up to 2 GB of file data with 8 KB cache blocks. It can grow
 * lazily on demand for larger files. Each inner array is a fixed-size
 * {@code Object[PAGE_SIZE]} (1024 slots / 8 KB), directly indexed by
 * the inner slot — no popcount, no COW. Inner arrays are reclaimed (nulled)
 * when all their slots become empty, keeping memory overhead proportional
 * to actual cached blocks.
 *
 * <h2>Thread safety and memory ordering</h2>
 * <ul>
 *   <li>Reads are lock-free: an acquire load of the {@link #directory} field, then an
 *       acquire load of the slot element. No locks, no CAS on the read path.</li>
 *   <li>Writes that PUBLISH or INVALIDATE state use release stores: slot writes in
 *       {@link #put}/{@link #remove} and the {@code directory} reassignment in
 *       {@link #clear}/{@code growDirectory}. Release/acquire pairing on the same
 *       variable establishes the happens-before edge that makes an invalidation
 *       (eviction null-out, table clear) reliably visible to concurrent readers.</li>
 *   <li>Plain (non-ordered) access is NOT sufficient here. This table is the L1 block
 *       cache and its cached values carry no generation counter or refcount; coherence
 *       relies on the L2-eviction callback ({@code RadixBlockTableRegistry#onEviction})
 *       and the delete/rename {@code clearFile} path actually clearing stale slots in a
 *       way readers observe. JLS §17.7 only guarantees reference reads/writes are not
 *       torn — it provides no visibility ordering; a plain null-out on the eviction
 *       thread had no happens-before edge to a reader's plain load, so a stale non-null
 *       entry could (in the JMM, and in principle under JIT load hoisting) survive an
 *       invalidation and serve the OLD inode's bytes after a delete-then-recreate at
 *       the same path — silent under the unauthenticated AES-CTR read path.</li>
 *   <li>On x86 acquire/release compile to plain loads/stores (no fence cost on the read
 *       path); on weakly-ordered hardware (aarch64/Graviton) they emit {@code ldar}/{@code stlr},
 *       which is the whole point.</li>
 *   <li>Stale-<em>null</em> reads remain benign: a missed publication is just an L1 miss,
 *       falling through to the Caffeine L2 cache, which is the source of truth.</li>
 *   <li>Inner-array allocation and reclamation are guarded by {@code synchronized(this)}
 *       to avoid allocation races; slot stores themselves are release stores.</li>
 * </ul>
 *
 * @param <V> the type of values stored in the table
 */
public final class RadixBlockTable<V> {

    /** Each inner array covers 1024 consecutive blockIds. */
    public static final int PAGE_SHIFT = 10;
    public static final int PAGE_SIZE = 1 << PAGE_SHIFT; // 1024
    private static final int PAGE_MASK = PAGE_SIZE - 1;   // 1023

    /**
     * Default outer directory size. 256 x 1024 = 262,144 block IDs.
     * With 8 KB cache blocks this covers 2 GB per file without growth.
     */
    public static final int DEFAULT_OUTER_SLOTS = 256;

    /**
     * Plain int counter for L2 damp signaling. Incremented on every L1 hit.
     * When (accessCounter &amp; SAMPLE_MASK) == 0, the caller touches L2 so Caffeine
     * sees the access frequency and doesn't evict hot blocks.
     *
     * <p>Not volatile — races can only lose increments (fewer L2 touches),
     * never corrupt state. int writes are atomic per JLS §17.7.
     * Overflow is safe — the mask check only looks at low bits.
     */
    int accessCounter;

    /** Touch L2 every 4096 L1 hits. Must be power of 2 minus 1. */
    static final int SAMPLE_MASK = 4095;

    /** Acquire/release element access for the inner {@code Object[]} slot arrays. */
    private static final VarHandle SLOT = MethodHandles.arrayElementVarHandle(Object[].class);

    /** Acquire/release access for the {@link #directory} field. */
    private static final VarHandle DIRECTORY;

    static {
        try {
            DIRECTORY = MethodHandles.lookup().findVarHandle(RadixBlockTable.class, "directory", Object[][].class);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * Outer directory: {@code directory[outer]} is either null (no inner array)
     * or an {@code Object[PAGE_SIZE]}. Grown on demand under synchronized; read
     * via {@link #DIRECTORY} acquire loads, republished via release stores.
     */
    private Object[][] directory;

    public RadixBlockTable() {
        this.directory = new Object[DEFAULT_OUTER_SLOTS][];
    }

    public RadixBlockTable(int initialOuterSlots) {
        this.directory = new Object[Math.max(initialOuterSlots, 1)][];
    }

    private Object[][] directoryAcquire() {
        return (Object[][]) DIRECTORY.getAcquire(this);
    }

    /**
     * Looks up the value for the given blockId.
     * Lock-free: one acquire load of the directory, one plain outer-element load,
     * one acquire load of the slot.
     *
     * @return the cached value, or null if not present (L1 miss)
     */
    @SuppressWarnings("unchecked")
    public V get(long blockId) {
        int outer = (int) (blockId >>> PAGE_SHIFT);
        Object[][] dir = directoryAcquire(); // single acquire read of the reference
        if (outer >= dir.length)
            return null;

        Object[] inner = dir[outer]; // outer elements are published by the release store of a slot or under sync
        if (inner == null)
            return null;

        int slot = (int) (blockId & PAGE_MASK);
        return (V) SLOT.getAcquire(inner, slot); // pairs with the release stores in put()/remove()
    }

    /**
     * Stores a value at the given blockId with release semantics, so a subsequent
     * acquire read in {@link #get} observes it (and everything before it).
     * Allocates the inner array lazily if needed (synchronized for allocation only).
     */
    public void put(long blockId, V value) {
        int outer = (int) (blockId >>> PAGE_SHIFT);
        int slot = (int) (blockId & PAGE_MASK);

        Object[][] dir = directoryAcquire();
        if (outer < dir.length) {
            Object[] inner = dir[outer];
            if (inner != null) {
                // Fast path: inner array exists, release store
                SLOT.setRelease(inner, slot, value);
                return;
            }
        }

        // Slow path: need to allocate inner array or grow directory
        putSlow(outer, slot, value);
    }

    private synchronized void putSlow(int outer, int slot, V value) {
        if (outer >= directory.length) {
            growDirectory(outer);
        }
        Object[] inner = directory[outer];
        if (inner == null) {
            inner = new Object[PAGE_SIZE];
            directory[outer] = inner;
            // Republish the directory so the new inner array becomes visible to
            // lock-free readers without requiring them to synchronize.
            DIRECTORY.setRelease(this, directory);
        }
        SLOT.setRelease(inner, slot, value);
    }

    /**
     * Removes (nulls) the entry at the given blockId with release semantics — this is
     * the L1 invalidation primitive fired by the L2 eviction callback, so the null-out
     * MUST be visible to concurrent lock-free readers (see class doc).
     * After nulling the slot, scans the inner array. If all slots are null,
     * the inner array is reclaimed (set to null) under synchronization.
     *
     * @return the previous value, or null if slot was empty
     */
    @SuppressWarnings("unchecked")
    public V remove(long blockId) {
        int outer = (int) (blockId >>> PAGE_SHIFT);
        Object[][] dir = directoryAcquire();
        if (outer >= dir.length)
            return null;

        Object[] inner = dir[outer];
        if (inner == null)
            return null;

        int slot = (int) (blockId & PAGE_MASK);
        V prev = (V) SLOT.getAcquire(inner, slot);
        SLOT.setRelease(inner, slot, null); // release store — pairs with get()'s acquire load

        // Check if inner array is now empty and reclaim if so
        if (prev != null) {
            reclaimIfEmpty(outer, inner);
        }
        return prev;
    }

    private synchronized void reclaimIfEmpty(int outer, Object[] inner) {
        if (directory[outer] != inner) {
            return;
        }
        for (int i = 0; i < PAGE_SIZE; i++) {
            if (SLOT.getAcquire(inner, i) != null) {
                return;
            }
        }
        directory[outer] = null;
        DIRECTORY.setRelease(this, directory);
    }

    /**
     * Clears all entries.
     * Swaps to a fresh empty directory of the same length with a release store, so
     * concurrent readers' next acquire load observes the empty table — this is the
     * invalidation path used by {@code clearFile} on delete/rename and by
     * {@code release()} when the last IndexInput closes, and it must take effect
     * for readers that keep running (see class doc).
     */
    public synchronized void clear() {
        DIRECTORY.setRelease(this, new Object[directory.length][]);
    }

    /**
     * Estimates the memory overhead of this table in bytes.
     */
    public long memoryOverheadBytes() {
        Object[][] dir = directoryAcquire();
        long overhead = 16;
        overhead += 16 + 4 + 4 + (long) dir.length * 8;
        for (Object[] inner : dir) {
            if (inner != null) {
                overhead += 16 + 4 + 4 + (long) PAGE_SIZE * 8;
            }
        }
        return overhead;
    }

    boolean isInnerAllocated(int outer) {
        Object[][] dir = directoryAcquire();
        return outer < dir.length && dir[outer] != null;
    }

    int directoryLength() {
        return directoryAcquire().length;
    }

    int countEntries(int outer) {
        Object[][] dir = directoryAcquire();
        if (outer >= dir.length)
            return -1;
        Object[] inner = dir[outer];
        if (inner == null)
            return -1;
        int count = 0;
        for (int i = 0; i < PAGE_SIZE; i++) {
            if (SLOT.getAcquire(inner, i) != null)
                count++;
        }
        return count;
    }

    int allocatedInnerCount() {
        Object[][] dir = directoryAcquire();
        int count = 0;
        for (Object[] inner : dir) {
            if (inner != null)
                count++;
        }
        return count;
    }

    private void growDirectory(int requiredOuter) {
        int newSize = Math.max(requiredOuter + 1, directory.length * 2);
        Object[][] newDir = new Object[newSize][];
        System.arraycopy(directory, 0, newDir, 0, directory.length);
        DIRECTORY.setRelease(this, newDir);
    }
}
