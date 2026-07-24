/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.Before;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.test.OpenSearchTestCase;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Tests for the {@code secondary} path index in {@link CaffeineBlockCache}.
 *
 * <p>The secondary index maps each {@link java.nio.file.Path} to the set of block-cache keys currently
 * cached for that path, so {@code invalidate(Path)} completes in O(K-file) via a single lookup instead
 * of an O(N-cache) scan over every cached block. These tests pin the invariants that behavior depends on:
 *
 * <ol>
 * <li>{@code put} and cache-miss {@code getOrLoad} both populate the secondary index.</li>
 * <li>{@code invalidate(Path)} clears both the primary cache entries AND the secondary entry for that path.</li>
 * <li>{@code invalidate(Path)} for {@code pathA} does not touch entries for {@code pathB}.</li>
 * </ol>
 *
 * <p>The removal-listener behavior that keeps the secondary consistent under eviction is covered in
 * {@link BlockCacheBuilderRemovalListenerTests}.
 */
@SuppressWarnings("unchecked")
public class CaffeineBlockCacheSecondaryIndexTests extends OpenSearchTestCase {

    private Cache<BlockCacheKey, BlockCacheValue<String>> caffeineCache;
    private BlockLoader<BlockCacheValue<String>> mockLoader;
    private CaffeineBlockCache<String, BlockCacheValue<String>> blockCache;
    private static final long MAX_BLOCKS = 100;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        caffeineCache = Caffeine.newBuilder().maximumSize(MAX_BLOCKS).recordStats().build();
        mockLoader = mock(BlockLoader.class);
        blockCache = new CaffeineBlockCache<>(caffeineCache, mockLoader, MAX_BLOCKS);
    }

    /**
     * put() must populate the secondary path index for the file. Without this, a later
     * {@code invalidate(Path)} would fall back to O(N-cache) scanning and — worse — miss the entries
     * entirely because {@code invalidate(Path)} removes from the secondary and then invalidates only the
     * key set it found there.
     */
    public void testPutPopulatesSecondaryIndex() {
        Path path = Paths.get("/test/file.dat");
        BlockCacheKey key = new FileBlockCacheKey(path, 0L);

        blockCache.put(key, createMockValue("data"));

        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary = readSecondary(blockCache);
        Path normalized = path.toAbsolutePath().normalize();
        assertNotNull("put must populate secondary index for file path", secondary.get(normalized));
        assertTrue("secondary entry must contain the inserted key", secondary.get(normalized).contains(key));
    }

    /**
     * getOrLoad() on a cache-miss must populate the secondary. Cache-hits should NOT re-add to the
     * secondary (they're already there from the original put/miss). This is the critical peer-recovery
     * path — every incoming block during recovery arrives via a getOrLoad miss.
     */
    public void testGetOrLoadCacheMissPopulatesSecondaryIndex() throws Exception {
        Path path = Paths.get("/test/recovery.cfs");
        BlockCacheKey key = new FileBlockCacheKey(path, 0L);
        BlockCacheValue<String> loaded = createMockValue("loaded");
        when(mockLoader.load(key)).thenReturn(loaded);

        BlockCacheValue<String> result = blockCache.getOrLoad(key);

        assertNotNull("getOrLoad result must not be null", result);
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary = readSecondary(blockCache);
        Path normalized = path.toAbsolutePath().normalize();
        assertNotNull("cache-miss getOrLoad must populate secondary", secondary.get(normalized));
        assertTrue("secondary must contain the loaded key", secondary.get(normalized).contains(key));
    }

    /**
     * invalidate(Path) must remove BOTH:
     * - all cache entries for that path from the primary Caffeine cache
     * - the path's entry from the secondary index
     *
     * <p>This is the O(K-file) fast path — a single {@code secondary.remove(path)} hands the fix the
     * exact keys to invalidate.
     */
    public void testInvalidatePathClearsPrimaryAndSecondary() {
        Path path = Paths.get("/test/multi.cfs");
        BlockCacheKey k0 = new FileBlockCacheKey(path, 0L);
        BlockCacheKey k1 = new FileBlockCacheKey(path, 1024L);
        BlockCacheKey k2 = new FileBlockCacheKey(path, 2048L);
        blockCache.put(k0, createMockValue("b0"));
        blockCache.put(k1, createMockValue("b1"));
        blockCache.put(k2, createMockValue("b2"));

        // Sanity check pre-conditions
        assertNotNull("k0 must be in primary before invalidate", blockCache.get(k0));
        assertNotNull("k1 must be in primary before invalidate", blockCache.get(k1));
        assertNotNull("k2 must be in primary before invalidate", blockCache.get(k2));
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary = readSecondary(blockCache);
        Path normalized = path.toAbsolutePath().normalize();
        assertNotNull("secondary must have entry before invalidate", secondary.get(normalized));

        blockCache.invalidate(path);

        // Primary side: all three block keys are gone from the Caffeine cache.
        // cleanUp() is called defensively to flush any pending removals synchronously — Caffeine's
        // invalidate returns before all book-keeping is done in some implementations, and test assertions
        // want a deterministic post-state.
        caffeineCache.cleanUp();
        assertNull("k0 must be gone from primary after invalidate(Path)", blockCache.get(k0));
        assertNull("k1 must be gone from primary after invalidate(Path)", blockCache.get(k1));
        assertNull("k2 must be gone from primary after invalidate(Path)", blockCache.get(k2));

        // Secondary side: the whole file-path entry is gone.
        secondary = readSecondary(blockCache);
        assertNull("secondary must have no entry for path after invalidate(Path)", secondary.get(normalized));
    }

    /**
     * invalidate(pathA) must NOT touch entries for pathB. Correctness under peer-recovery load: many
     * files are cached concurrently, and cleanFiles calls invalidate on one file at a time; a leakage
     * bug would silently corrupt the cache for unrelated live files.
     */
    public void testInvalidatePathDoesNotAffectOtherPaths() {
        Path pathA = Paths.get("/test/fileA.cfs");
        Path pathB = Paths.get("/test/fileB.cfs");
        BlockCacheKey a0 = new FileBlockCacheKey(pathA, 0L);
        BlockCacheKey a1 = new FileBlockCacheKey(pathA, 1024L);
        BlockCacheKey b0 = new FileBlockCacheKey(pathB, 0L);
        BlockCacheKey b1 = new FileBlockCacheKey(pathB, 1024L);
        BlockCacheValue<String> vB0 = createMockValue("b0");
        BlockCacheValue<String> vB1 = createMockValue("b1");
        blockCache.put(a0, createMockValue("a0"));
        blockCache.put(a1, createMockValue("a1"));
        blockCache.put(b0, vB0);
        blockCache.put(b1, vB1);

        blockCache.invalidate(pathA);
        caffeineCache.cleanUp();

        // pathA is gone from primary and secondary
        assertNull("a0 must be gone", blockCache.get(a0));
        assertNull("a1 must be gone", blockCache.get(a1));
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary = readSecondary(blockCache);
        assertNull("secondary must not have pathA entry", secondary.get(pathA.toAbsolutePath().normalize()));

        // pathB is untouched in primary AND secondary
        assertSame("b0 must remain in primary", vB0, blockCache.get(b0));
        assertSame("b1 must remain in primary", vB1, blockCache.get(b1));
        Set<BlockCacheKey> keysB = secondary.get(pathB.toAbsolutePath().normalize());
        assertNotNull("secondary must still have pathB entry", keysB);
        assertTrue("secondary pathB set must contain b0", keysB.contains(b0));
        assertTrue("secondary pathB set must contain b1", keysB.contains(b1));
    }

    // Reflection helper — the secondary field is package-private-encapsulated behind a private final
    // reference. Testing internal invariants of the fix is legitimate; we don't want to widen the API
    // just for tests. Reflection is stable here because the field name is set in stone by the fix.
    @SuppressWarnings("unchecked")
    private static ConcurrentHashMap<Path, Set<BlockCacheKey>> readSecondary(CaffeineBlockCache<?, ?> cache) {
        try {
            Field f = CaffeineBlockCache.class.getDeclaredField("secondary");
            f.setAccessible(true);
            return (ConcurrentHashMap<Path, Set<BlockCacheKey>>) f.get(cache);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("Failed to reflect CaffeineBlockCache.secondary — path index missing?", e);
        }
    }

    private BlockCacheValue<String> createMockValue(String data) {
        BlockCacheValue<String> value = mock(BlockCacheValue.class);
        when(value.value()).thenReturn(data);
        return value;
    }
}
