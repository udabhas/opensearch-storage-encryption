/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.lucene.store.ByteBuffersDirectory;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.junit.Before;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTable;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTableRegistry;
import org.opensearch.index.store.bufferpoolfs.StaticConfigs;
import org.opensearch.test.BouncyCastleThreadFilter;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Tests for {@link CachedRandomAccessInput}, the block-cache-backed RandomAccessInput used by
 * {@code CryptoBufferedIndexInput#randomAccessSlice}.
 *
 * <p>This is a BASELINE subset ported from the fork's test suite: it covers only the behaviours that
 * match this branch's CURRENT implementation — scalar and bulk reads served from the cached block,
 * block-straddling reads falling back to disk, cache-miss fallback, offset (base) mapping, and L1
 * publish coherence for transient vs non-transient values. Tests that assert un-ported fixes
 * (bounds/EOF enforcement, L1 stale re-check, L2 damp sampling, one-resolution-per-block bulk reads,
 * reachabilityFence wrapper handling, and straddle-vs-fault metric separation) are intentionally
 * excluded — see the note at the end of this file.
 */
@SuppressWarnings("unchecked")
@ThreadLeakFilters(filters = { CaffeineThreadLeakFilter.class, BouncyCastleThreadFilter.class })
public class CachedRandomAccessInputTests extends OpenSearchTestCase {

    private static final int BLOCK_SIZE = StaticConfigs.CACHE_BLOCK_SIZE;
    private static final long BLOCK_MASK = StaticConfigs.CACHE_BLOCK_MASK;
    private static final ValueLayout.OfByte LAYOUT_BYTE = ValueLayout.JAVA_BYTE;
    private static final ValueLayout.OfShort LE_SHORT = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfInt LE_INT = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfLong LE_LONG = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    private BlockCache<RefCountedByteBuffer> mockCache;
    private RadixBlockTableRegistry registry;
    private RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixTable;
    private Path testPath;
    private Arena arena;
    private Directory scratchDir;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        mockCache = mock(BlockCache.class);
        testPath = Paths.get("/test/randomaccess.dat");
        registry = new RadixBlockTableRegistry();
        radixTable = registry.acquire(testPath);
        arena = Arena.ofAuto();
        scratchDir = new ByteBuffersDirectory();
    }

    public void testLengthReportsSliceLength() throws IOException {
        final CachedRandomAccessInput in = inputWithBlockOfBytes(0L, 123L, (byte) 0, diskWithBytes(123L, (byte) 0));
        assertEquals(123L, in.length());
    }

    // ---- scalar reads served from the cached block ----

    public void testScalarReadsFromCachedBlock() throws IOException {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        block.set(LAYOUT_BYTE, 0, (byte) 0x11);
        block.set(LE_SHORT, 8, (short) 0x2233);
        block.set(LE_INT, 16, 0x44556677);
        block.set(LE_LONG, 32, 0x0102030405060708L);
        final CachedRandomAccessInput in = inputForBlock(block, 0L, BLOCK_SIZE, diskWithBytes(BLOCK_SIZE, (byte) 0));

        assertEquals((byte) 0x11, in.readByte(0));
        assertEquals((short) 0x2233, in.readShort(8));
        assertEquals(0x44556677, in.readInt(16));
        assertEquals(0x0102030405060708L, in.readLong(32));
    }

    public void testReadBytesBulkFromCachedBlock() throws IOException {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        for (int i = 0; i < 256; i++) {
            block.set(LAYOUT_BYTE, i, (byte) i);
        }
        final CachedRandomAccessInput in = inputForBlock(block, 0L, BLOCK_SIZE, diskWithBytes(BLOCK_SIZE, (byte) 0));

        final byte[] out = new byte[128];
        in.readBytes(4, out, 0, 128);
        for (int i = 0; i < 128; i++) {
            assertEquals("bulk byte " + i, (byte) (i + 4), out[i]);
        }
    }

    public void testReadBytesZeroLengthIsNoOp() throws IOException {
        final CachedRandomAccessInput in = inputWithBlockOfBytes(0L, 16L, (byte) 0x5A, diskWithBytes(16L, (byte) 0x5A));
        final byte[] out = new byte[4];
        in.readBytes(0, out, 0, 0);
        assertEquals("untouched", (byte) 0, out[0]);
    }

    // ---- cross-block reads must fall back to disk and still return the right bytes ----

    public void testBlockStraddlingReadsFallBackToDiskAndAreCorrect() throws IOException {
        // Cached block deliberately holds a different pattern than disk, so a wrong-path read is detectable.
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block.set(LAYOUT_BYTE, i, (byte) 0xFF);
        }
        final long len = BLOCK_SIZE + 64;
        final IndexInput disk = diskWithCounterPattern(len);
        final CachedRandomAccessInput in = inputForBlock(block, 0L, len, disk);

        // A long starting 4 bytes before the block end straddles into the next block -> disk path.
        final long pos = BLOCK_SIZE - 4;
        final long expected = expectedLongFromCounterPattern(pos);
        assertEquals("straddling long must come from disk", expected, in.readLong(pos));
    }

    // ---- cache-miss fallback ----

    public void testCacheMissFallsBackToDisk() throws IOException {
        when(mockCache.get(any(FileBlockCacheKey.class))).thenReturn(null);
        when(mockCache.getOrLoad(any(FileBlockCacheKey.class))).thenReturn(null);
        final long len = 32;
        final IndexInput disk = diskWithCounterPattern(len);
        final CachedRandomAccessInput in = new CachedRandomAccessInput(testPath, 0L, len, BLOCK_MASK, mockCache, null, null, disk);
        assertEquals("byte 0 from disk", (byte) 0, in.readByte(0));
        assertEquals("byte 5 from disk", (byte) 5, in.readByte(5));
    }

    public void testNullRadixTableStillReadsViaL2() throws IOException {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        block.set(LAYOUT_BYTE, 3, (byte) 0x39);
        final BlockCacheValue<RefCountedByteBuffer> value = cacheValueFor(block, false);
        when(mockCache.get(any(FileBlockCacheKey.class))).thenReturn(value);
        when(mockCache.getOrLoad(any(FileBlockCacheKey.class))).thenReturn(value);

        final CachedRandomAccessInput in = new CachedRandomAccessInput(
            testPath,
            0L,
            BLOCK_SIZE,
            BLOCK_MASK,
            mockCache,
            null,
            null,
            diskWithBytes(BLOCK_SIZE, (byte) 0)
        );
        assertEquals((byte) 0x39, in.readByte(3));
    }

    // ---- L1 publish coherence: a transient (degraded-mode) buffer must never enter L1 ----

    public void testTransientValueIsNotPublishedToL1() throws IOException {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        block.set(LAYOUT_BYTE, 0, (byte) 0x6B);
        final BlockCacheValue<RefCountedByteBuffer> transientValue = cacheValueFor(block, true);
        when(mockCache.get(any(FileBlockCacheKey.class))).thenReturn(transientValue);
        when(mockCache.getOrLoad(any(FileBlockCacheKey.class))).thenReturn(transientValue);

        final CachedRandomAccessInput in = new CachedRandomAccessInput(
            testPath,
            0L,
            BLOCK_SIZE,
            BLOCK_MASK,
            mockCache,
            radixTable,
            registry,
            diskWithBytes(BLOCK_SIZE, (byte) 0)
        );
        assertEquals((byte) 0x6B, in.readByte(0));
        assertNull("transient value must not be installed in L1", radixTable.get(0L));
    }

    public void testNonTransientValueIsPublishedToL1WhenL2StillHoldsIt() throws IOException {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        block.set(LAYOUT_BYTE, 0, (byte) 0x4D);
        final BlockCacheValue<RefCountedByteBuffer> value = cacheValueFor(block, false);
        when(mockCache.get(any(FileBlockCacheKey.class))).thenReturn(value);
        when(mockCache.getOrLoad(any(FileBlockCacheKey.class))).thenReturn(value);

        final CachedRandomAccessInput in = new CachedRandomAccessInput(
            testPath,
            0L,
            BLOCK_SIZE,
            BLOCK_MASK,
            mockCache,
            radixTable,
            registry,
            diskWithBytes(BLOCK_SIZE, (byte) 0)
        );
        assertEquals((byte) 0x4D, in.readByte(0));
        assertNotNull("L1 should hold the published block", radixTable.get(0L));
    }

    // ---- offset (base) handling: a slice not starting at 0 must map positions correctly ----

    public void testSliceBaseOffsetMapsIntoBlock() throws IOException {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        block.set(LAYOUT_BYTE, 100, (byte) 0x5E);
        final long base = 100;
        final BlockCacheValue<RefCountedByteBuffer> value = cacheValueFor(block, false);
        when(mockCache.get(any(FileBlockCacheKey.class))).thenReturn(value);
        when(mockCache.getOrLoad(any(FileBlockCacheKey.class))).thenReturn(value);

        // slice-relative position 0 == absolute 100
        final CachedRandomAccessInput in = new CachedRandomAccessInput(
            testPath,
            base,
            16,
            BLOCK_MASK,
            mockCache,
            radixTable,
            registry,
            diskWithBytes(16, (byte) 0)
        );
        assertEquals((byte) 0x5E, in.readByte(0));
    }

    // ---- bulk readBytes ----

    /** A run wholly inside one block must be copied correctly. */
    public void testReadBytesWithinSingleBlock() throws IOException {
        final CachedRandomAccessInput in = inputForBlock(counterPatternBlock(), 0L, BLOCK_SIZE, diskWithCounterPattern(BLOCK_SIZE));
        final byte[] out = new byte[256];
        in.readBytes(10, out, 0, 256);
        for (int i = 0; i < 256; i++) {
            assertEquals("byte " + i, (byte) (10 + i), out[i]);
        }
    }

    /** Writing into the middle of the caller's array must respect the array offset. */
    public void testReadBytesHonoursArrayOffset() throws IOException {
        final CachedRandomAccessInput in = inputForBlock(counterPatternBlock(), 0L, BLOCK_SIZE, diskWithCounterPattern(BLOCK_SIZE));
        final byte[] out = new byte[64];
        java.util.Arrays.fill(out, (byte) 0x7A);
        in.readBytes(0, out, 16, 32);
        assertEquals("before the window is untouched", (byte) 0x7A, out[15]);
        assertEquals("window start", (byte) 0, out[16]);
        assertEquals("window end", (byte) 31, out[47]);
        assertEquals("after the window is untouched", (byte) 0x7A, out[48]);
    }

    /** A span crossing a block boundary must stitch both blocks together correctly. */
    public void testReadBytesSpanningTwoBlocks() throws IOException {
        // Two blocks with distinct fills; the disk fallback carries the same bytes so either path is correct.
        final MemorySegment block0 = arena.allocate(BLOCK_SIZE);
        final MemorySegment block1 = arena.allocate(BLOCK_SIZE);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block0.set(LAYOUT_BYTE, i, (byte) 0xA1);
            block1.set(LAYOUT_BYTE, i, (byte) 0xB2);
        }
        final BlockCacheValue<RefCountedByteBuffer> v0 = cacheValueFor(block0, false);
        final BlockCacheValue<RefCountedByteBuffer> v1 = cacheValueFor(block1, false);
        when(mockCache.get(new FileBlockCacheKey(testPath, 0L))).thenReturn(v0);
        when(mockCache.getOrLoad(new FileBlockCacheKey(testPath, 0L))).thenReturn(v0);
        when(mockCache.get(new FileBlockCacheKey(testPath, (long) BLOCK_SIZE))).thenReturn(v1);
        when(mockCache.getOrLoad(new FileBlockCacheKey(testPath, (long) BLOCK_SIZE))).thenReturn(v1);

        final long len = 2L * BLOCK_SIZE;
        final CachedRandomAccessInput in = new CachedRandomAccessInput(
            testPath,
            0L,
            len,
            BLOCK_MASK,
            mockCache,
            null,
            null,
            diskWithBytes(len, (byte) 0xA1)
        );

        final byte[] out = new byte[16];
        in.readBytes(BLOCK_SIZE - 8, out, 0, 16); // 8 bytes from block0, 8 from block1
        for (int i = 0; i < 8; i++) {
            assertEquals("tail of block0 at " + i, (byte) 0xA1, out[i]);
        }
        for (int i = 8; i < 16; i++) {
            assertEquals("head of block1 at " + i, (byte) 0xB2, out[i]);
        }
    }

    /** When the cache cannot serve a block, the whole remaining span must come from disk, fully populated. */
    public void testReadBytesFallsBackToDiskOnCacheMiss() throws IOException {
        when(mockCache.get(any(FileBlockCacheKey.class))).thenReturn(null);
        when(mockCache.getOrLoad(any(FileBlockCacheKey.class))).thenReturn(null);
        final long len = 128;
        final CachedRandomAccessInput in = new CachedRandomAccessInput(
            testPath,
            0L,
            len,
            BLOCK_MASK,
            mockCache,
            null,
            null,
            diskWithCounterPattern(len)
        );
        final byte[] out = new byte[64];
        in.readBytes(0, out, 0, 64);
        for (int i = 0; i < 64; i++) {
            assertEquals("disk byte " + i, (byte) i, out[i]);
        }
    }

    /** A full block whose length is a whole block must copy without a stray extra iteration. */
    public void testReadBytesExactlyOneFullBlock() throws IOException {
        final CachedRandomAccessInput in = inputForBlock(counterPatternBlock(), 0L, BLOCK_SIZE, diskWithCounterPattern(BLOCK_SIZE));
        final byte[] out = new byte[BLOCK_SIZE];
        in.readBytes(0, out, 0, BLOCK_SIZE);
        assertEquals("first", (byte) 0, out[0]);
        assertEquals("last", (byte) ((BLOCK_SIZE - 1) & 0xFF), out[BLOCK_SIZE - 1]);
    }

    // ---------------- helpers ----------------

    /** A block whose bytes are (byte) index, for order-sensitive assertions. */
    private MemorySegment counterPatternBlock() {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block.set(LAYOUT_BYTE, i, (byte) i);
        }
        return block;
    }

    private BlockCacheValue<RefCountedByteBuffer> cacheValueFor(MemorySegment segment, boolean isTransient) {
        final RefCountedByteBuffer ref = new RefCountedByteBuffer(segment.asByteBuffer(), (int) segment.byteSize());
        final BlockCacheValue<RefCountedByteBuffer> value = mock(BlockCacheValue.class);
        when(value.value()).thenReturn(ref);
        when(value.tryPin()).thenReturn(true);
        when(value.isTransient()).thenReturn(isTransient);
        return value;
    }

    private CachedRandomAccessInput inputForBlock(MemorySegment block, long base, long len, IndexInput disk) throws IOException {
        final BlockCacheValue<RefCountedByteBuffer> value = cacheValueFor(block, false);
        when(mockCache.get(any(FileBlockCacheKey.class))).thenReturn(value);
        when(mockCache.getOrLoad(any(FileBlockCacheKey.class))).thenReturn(value);
        return new CachedRandomAccessInput(testPath, base, len, BLOCK_MASK, mockCache, radixTable, registry, disk);
    }

    private CachedRandomAccessInput inputWithBlockOfBytes(long base, long len, byte fill, IndexInput disk) throws IOException {
        final MemorySegment block = arena.allocate(BLOCK_SIZE);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block.set(LAYOUT_BYTE, i, fill);
        }
        return inputForBlock(block, base, len, disk);
    }

    /** A real on-disk-style IndexInput over {@code len} bytes all equal to {@code fill}. */
    private IndexInput diskWithBytes(long len, byte fill) throws IOException {
        final byte[] data = new byte[(int) len];
        java.util.Arrays.fill(data, fill);
        return writeAndOpen(data);
    }

    /** A real IndexInput whose byte at position i is (byte) i -- lets a test detect which path served a read. */
    private IndexInput diskWithCounterPattern(long len) throws IOException {
        final byte[] data = new byte[(int) len];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        return writeAndOpen(data);
    }

    /** Little-endian long of the 8 counter-pattern bytes starting at {@code pos} (byte i == (byte) i). */
    private long expectedLongFromCounterPattern(long pos) {
        long v = 0L;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | ((long) (byte) (pos + i) & 0xFFL);
        }
        return v;
    }

    private IndexInput writeAndOpen(byte[] data) throws IOException {
        final String name = "disk-" + data.length + "-" + randomAlphaOfLength(6) + ".bin";
        try (IndexOutput out = scratchDir.createOutput(name, IOContext.DEFAULT)) {
            out.writeBytes(data, 0, data.length);
        }
        return scratchDir.openInput(name, IOContext.DEFAULT);
    }

    /*
     * ==================== EXCLUDED / PENDING TESTS ====================
     *
     * The following tests were present in the fork's CachedRandomAccessInputTests but are NOT ported
     * here because they assert behaviour that this branch's CachedRandomAccessInput does not yet
     * implement. Each would fail (or not compile) against the current production source. They should
     * be re-introduced together with the corresponding fix.
     *
     * (#1) Bounds / EOF enforcement — current reads do not validate pos against [0, len); an over-read
     *      or negative position is not rejected (it silently falls through to disk / reads pooled tail):
     *        - testReadPastEndThrowsEofForEachWidth
     *        - testNegativePositionThrows
     *        - testLastValidReadOfEachWidthSucceeds
     *        - testReadBytesPastEndThrows
     *      Fix: add an ensureInBounds(pos, width) guard that throws EOFException.
     *
     * (#2) L1 publish coherence re-check — current publish is a bare radixTable.put(blockId, value)
     *      with no post-publish L2 re-check, so a stale L1 entry can survive when L2 no longer holds
     *      the key:
     *        - testStaleL1EntryIsRemovedWhenL2NoLongerHoldsTheKey
     *      Fix: after put(), re-check cache.get(key); if now null, radixTable.remove(blockId).
     *
     * (#4) L2 damp sampling — current pinBlock does a plain radixTable.get() on an L1 hit and never
     *      touches L2, so there is no sampled recordL1HitAndShouldTouchL2 cadence to observe:
     *        - testL1HitsBelowSampleThresholdDoNotTouchL2
     *        - testL1HitAtSampleThresholdTouchesL2Once
     *        - testL2TouchRepeatsEverySamplePeriod
     *        - testL2TouchUsesTheBlockOffsetBeingRead
     *      Fix: on an L1 hit, sample via RadixBlockTable (SAMPLE_MASK) and touch cache.get(key) every
     *      4096th hit.
     *
     * (#5) readBytes per-block resolution — current class has no readBytes override, so it inherits
     *      RandomAccessInput's byte-at-a-time default (one block resolution per byte, not per block):
     *        - testReadBytesResolvesBlockOncePerBlockNotPerByte
     *      Fix: override readBytes to resolve each block once and bulk-copy.
     *
     * (#6) use-after-free / reachabilityFence — current pinBlock returns a MemorySegment (not the
     *      BlockCacheValue wrapper) and no read method fences the wrapper:
     *        - testPinBlockReturnsTheCacheValueSoCallersCanFenceIt
     *        - testEveryReadMethodFencesTheWrapper
     *      Fix: return the BlockCacheValue from pinBlock and Reference.reachabilityFence(value) in each
     *      read path.
     *
     * (#7) straddle-vs-fault metric separation — current class records no metrics at all on the
     *      random-access path, and decides the straddle only AFTER resolving a block:
     *        - testStraddlingReadIsMeteredAsStraddleNotAsFault
     *        - testUnavailableBlockIsMeteredAsFault
     *        - testStraddleIsDecidedWithoutResolvingABlock
     *      Fix: add ErrorType.RANDOM_ACCESS_BLOCK_STRADDLE, meter straddle vs fault distinctly, and
     *      perform the straddle check before block resolution.
     */
}
