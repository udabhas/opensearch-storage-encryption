/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentHashMap;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for the two-level {@code frameIvCache} in {@link EncryptionMetadataCache}.
 *
 * <p>The frame-IV cache is keyed as a nested {@code Map<String, Map<Long, CachedFrameIv>>} (path →
 * frameNumber → cached IV) so {@code invalidateFile(path)} completes in O(1) via a single
 * {@code map.remove(path)}. A flatter layout — e.g. {@code Map<FrameKey, byte[]>} keyed by a composite
 * of (path, frameNumber) — would force an O(N-cache) scan on the peer-recovery {@code deleteFile} hot
 * path, and on nodes with millions of cached IVs that scan can exceed the 60 s {@code clean_files}
 * transport ceiling.
 *
 * <p>These tests pin the two invariants that behavior relies on:
 * <ol>
 * <li>{@code invalidateFile(path)} drops the entire per-path IV map for that path in a single remove
 *     (no scan of other paths).</li>
 * <li>Frame IVs are keyed nested: {@code frameIvCache.get(path)} returns a {@code Map<Long,
 *     CachedFrameIv>} keyed by frameNumber — proving the O(1) invalidation path is real and not a
 *     residual flat layout.</li>
 * </ol>
 */
public class EncryptionMetadataCacheFrameIvTests extends OpenSearchTestCase {

    private static final byte[] MSG_ID_A = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    private static final byte[] MSG_ID_B = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2 };
    private static final byte[] IV_1 = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    private static final byte[] IV_2 = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    private static final byte[] IV_3 = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };

    /**
     * invalidateFile(path) MUST drop the entire per-path frame-IV entry from the top-level map (not
     * just some frames). This is the O(1) fast path that the nested-map layout enables.
     *
     * <p>The Track 6 hot path (renameTempFilesSafe → deleteFile → invalidateFile) runs sequentially
     * per file; a variant that scanned or partially cleared would recreate the timeout regression
     * the fix addresses.
     */
    public void testInvalidateFileClearsAllFramesForThatPath() {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        String pathA = "/test/fileA.cfs";

        // Populate 3 frames for pathA — proves the invalidate path handles more than a single frame
        // (typical files have 1 frame with the default 32 GB frame size, but the invariant must hold
        // for multi-frame files too).
        cache.putFrameIv(pathA, 0L, MSG_ID_A, IV_1);
        cache.putFrameIv(pathA, 1L, MSG_ID_A, IV_2);
        cache.putFrameIv(pathA, 2L, MSG_ID_A, IV_3);

        assertNotNull("frame 0 present pre-invalidate", cache.getFrameIv(pathA, 0L, MSG_ID_A));
        assertNotNull("frame 1 present pre-invalidate", cache.getFrameIv(pathA, 1L, MSG_ID_A));
        assertNotNull("frame 2 present pre-invalidate", cache.getFrameIv(pathA, 2L, MSG_ID_A));
        ConcurrentHashMap<String, ?> frameIvCache = readFrameIvCache(cache);
        assertTrue("frameIvCache must have entry for pathA before invalidate", frameIvCache.containsKey(pathA));

        cache.invalidateFile(pathA);

        // Every frame is gone from the public API...
        assertNull("frame 0 gone after invalidateFile", cache.getFrameIv(pathA, 0L, MSG_ID_A));
        assertNull("frame 1 gone after invalidateFile", cache.getFrameIv(pathA, 1L, MSG_ID_A));
        assertNull("frame 2 gone after invalidateFile", cache.getFrameIv(pathA, 2L, MSG_ID_A));

        // ...and the entire per-path entry is gone from the top-level map (proves it was a single
        // remove, not a partial clear).
        frameIvCache = readFrameIvCache(cache);
        assertFalse("frameIvCache must not have entry for pathA after invalidateFile", frameIvCache.containsKey(pathA));
    }

    /**
     * invalidateFile(pathA) must NOT touch pathB's frame IVs. Correctness across concurrent files —
     * cleanFiles invalidates one path at a time, and a leakage bug would silently drop IVs for live
     * files.
     */
    public void testInvalidateFileDoesNotAffectOtherPaths() {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        String pathA = "/test/fileA.cfs";
        String pathB = "/test/fileB.cfs";

        cache.putFrameIv(pathA, 0L, MSG_ID_A, IV_1);
        cache.putFrameIv(pathB, 0L, MSG_ID_B, IV_2);
        cache.putFrameIv(pathB, 1L, MSG_ID_B, IV_3);

        cache.invalidateFile(pathA);

        // pathA gone
        assertNull("pathA frame 0 gone", cache.getFrameIv(pathA, 0L, MSG_ID_A));

        // pathB untouched
        byte[] b0 = cache.getFrameIv(pathB, 0L, MSG_ID_B);
        byte[] b1 = cache.getFrameIv(pathB, 1L, MSG_ID_B);
        assertNotNull("pathB frame 0 must remain after pathA invalidate", b0);
        assertNotNull("pathB frame 1 must remain after pathA invalidate", b1);
        assertArrayEquals("pathB frame 0 IV bytes must match what was put", IV_2, b0);
        assertArrayEquals("pathB frame 1 IV bytes must match what was put", IV_3, b1);

        // Structural check: top-level frameIvCache still has pathB's entry, and it holds both frames.
        ConcurrentHashMap<String, ?> frameIvCache = readFrameIvCache(cache);
        assertFalse("pathA must be gone from frameIvCache", frameIvCache.containsKey(pathA));
        assertTrue("pathB must remain in frameIvCache", frameIvCache.containsKey(pathB));
        Object innerB = frameIvCache.get(pathB);
        assertTrue("inner must be a Map (nested layout)", innerB instanceof java.util.Map);
        assertEquals("pathB inner must have both frames", 2, ((java.util.Map<?, ?>) innerB).size());
    }

    /**
     * Frame IVs are keyed as a NESTED map (path → frameNumber → CachedFrameIv) — NOT a flat
     * (path,frameNumber)-composite map. This is the structural invariant that makes
     * {@code invalidateFile} O(1) (single remove on the outer map).
     *
     * <p>Without the nested shape, a regression back to a flat map would reintroduce O(N-cache) scan
     * behavior on the peer-recovery hot path and re-open the Track 6 timeout window. Testing the
     * shape at the reflection layer catches such a regression at build time.
     */
    public void testFrameIvCacheHasNestedShape() {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        String path = "/test/nested.cfs";
        cache.putFrameIv(path, 0L, MSG_ID_A, IV_1);
        cache.putFrameIv(path, 1L, MSG_ID_A, IV_2);

        // Verify the reflected field's runtime type + shape.
        ConcurrentHashMap<String, ?> outer = readFrameIvCache(cache);
        Object inner = outer.get(path);
        assertNotNull("outer map must have entry for path", inner);
        assertTrue("inner must be a Map (nested layout — required for O(1) invalidateFile)", inner instanceof java.util.Map);

        java.util.Map<?, ?> innerMap = (java.util.Map<?, ?>) inner;
        assertEquals("inner map must have both frame entries", 2, innerMap.size());

        // The inner map keys must be Long (frame numbers). A regression to (path,frame)-composite
        // keys on the outer map would fail here — the outer would key by a composite type and the
        // inner map wouldn't have Long keys.
        for (Object k : innerMap.keySet()) {
            assertTrue("inner map keys must be Long (frame numbers), was " + (k == null ? "null" : k.getClass()), k instanceof Long);
        }
    }

    @SuppressWarnings("unchecked")
    private static ConcurrentHashMap<String, ?> readFrameIvCache(EncryptionMetadataCache cache) {
        try {
            Field f = EncryptionMetadataCache.class.getDeclaredField("frameIvCache");
            f.setAccessible(true);
            return (ConcurrentHashMap<String, ?>) f.get(cache);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to reflect EncryptionMetadataCache.frameIvCache — nested map missing?", e);
        }
    }
}
