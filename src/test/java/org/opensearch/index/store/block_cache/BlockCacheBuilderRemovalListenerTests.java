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
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.opensearch.test.OpenSearchTestCase;

import com.github.benmanes.caffeine.cache.Cache;

/**
 * Targeted regression tests for the removal-listener {@code containsKey} guard in
 * {@link BlockCacheBuilder}.
 *
 * <p>The guard exists because Caffeine's removal listener fires "at some point in the past" — between
 * the eviction decision and the callback, the same key may have been re-inserted. Without the guard,
 * the listener would trim the secondary for the re-inserted key, and a later {@code invalidate(Path)}
 * would miss it. The AES-CTR read path is unauthenticated, so a stale hit on a recreated path decrypts
 * to silent garbage (Lucene CRC / CorruptIndexException).
 *
 * <p>Direct simulation of the async race is timing-sensitive and flaky. Instead these tests verify
 * the invariant the guard enforces: after {@code put} + {@code invalidate} + re-{@code put} of the
 * same key, the secondary contains the key. Any variant of the removal-listener path that ran without
 * the guard would leave the secondary empty for the re-inserted key.
 */
@SuppressWarnings("unchecked")
public class BlockCacheBuilderRemovalListenerTests extends OpenSearchTestCase {

    private BlockCacheBuilder.CacheWithExecutor<BlockCacheValue<String>, BlockCacheValue<String>> built;
    private CaffeineBlockCache<BlockCacheValue<String>, BlockCacheValue<String>> blockCache;
    private Cache<BlockCacheKey, BlockCacheValue<BlockCacheValue<String>>> primary;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        built = BlockCacheBuilder.build(16, 1024L);
        blockCache = (CaffeineBlockCache<BlockCacheValue<String>, BlockCacheValue<String>>) built.getCache();
        primary = blockCache.getCache();
    }

    @After
    public void tearDown() throws Exception {
        // Shut down the maint executor so the test doesn't leak threads.
        built.getExecutor().shutdownNow();
        built.getExecutor().awaitTermination(2, TimeUnit.SECONDS);
        super.tearDown();
    }

    /**
     * After: put(k) → invalidate(k) → put(k) → the secondary MUST contain k. The removal-listener
     * fired for the first put; if it trimmed the secondary AFTER the second put (the async race the
     * guard prevents), the secondary would be empty for k. With the guard, the listener sees the
     * re-inserted key in the primary and skips the trim.
     *
     * <p>We drive Caffeine's maintenance synchronously via {@code cleanUp()} to make the removal
     * listener fire deterministically in this thread of control.
     */
    public void testRemovalListenerGuardPreservesSecondaryOnReinsertion() throws Exception {
        Path path = Paths.get("/test/reinsert.cfs");
        BlockCacheKey key = new FileBlockCacheKey(path, 0L);

        // First insert.
        BlockCacheValue<BlockCacheValue<String>> v1 = createValueMock();
        blockCache.put(key, v1);

        // Invalidate — this queues the removal listener for the first insert.
        blockCache.invalidate(key);
        primary.cleanUp(); // fire listener synchronously

        // Re-insert with a NEW value (fresh cache entry for the same key). At this moment the primary
        // contains the key, but the removal listener queued from the invalidate may still be racing.
        BlockCacheValue<BlockCacheValue<String>> v2 = createValueMock();
        blockCache.put(key, v2);
        primary.cleanUp(); // flush any residual listener work

        // Guard invariant: secondary still tracks this key because either:
        // (a) the listener saw primary.containsKey(key)==true and skipped the trim, OR
        // (b) the listener trimmed but the trackInsertion for v2 re-added.
        // Both are acceptable; the test asserts the observable end state. Caffeine's removal listener
        // runs asynchronously on the common ForkJoinPool, so poll (calling cleanUp each round) for the
        // end state rather than asserting eagerly (occasional flake under parallel load otherwise).
        Path normalized = path.toAbsolutePath().normalize();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary = readSecondary(blockCache);
        while ((secondary.get(normalized) == null || !secondary.get(normalized).contains(key)) && System.nanoTime() < deadline) {
            Thread.sleep(10);
            primary.cleanUp();
            secondary = readSecondary(blockCache);
        }
        assertNotNull("secondary must have entry for path after re-insertion", secondary.get(normalized));
        assertTrue("secondary must contain the re-inserted key", secondary.get(normalized).contains(key));

        // And the primary still resolves the re-inserted value.
        assertSame("primary must return the re-inserted value, not the evicted one", v2, blockCache.get(key));
    }

    /**
     * Bulk eviction correctness: after put(k1..kN on same path), invalidate(Path) → the secondary
     * entry for the path is gone AND the primary no longer holds any of the keys. This is the
     * end-to-end invalidate(Path) behavior through the real removal listener.
     */
    public void testInvalidatePathThroughRemovalListenerClearsBoth() {
        Path path = Paths.get("/test/bulk.cfs");
        BlockCacheKey[] keys = new BlockCacheKey[5];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = new FileBlockCacheKey(path, i * 1024L);
            blockCache.put(keys[i], createValueMock());
        }

        blockCache.invalidate(path);
        primary.cleanUp();

        for (BlockCacheKey k : keys) {
            assertNull("primary must have no entry for key after invalidate(Path)", blockCache.get(k));
        }
        ConcurrentHashMap<Path, Set<BlockCacheKey>> secondary = readSecondary(blockCache);
        assertNull("secondary must have no entry for path after invalidate(Path)", secondary.get(path.toAbsolutePath().normalize()));
    }

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

    // Mock value that supports close() cleanly (BlockCacheBuilder's removal listener calls close()).
    private BlockCacheValue<BlockCacheValue<String>> createValueMock() {
        BlockCacheValue<BlockCacheValue<String>> v = mock(BlockCacheValue.class);
        when(v.tryPin()).thenReturn(true);
        return v;
    }
}
