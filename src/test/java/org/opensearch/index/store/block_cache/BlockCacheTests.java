/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.test.OpenSearchTestCase;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

@SuppressWarnings("preview")
public class BlockCacheTests extends OpenSearchTestCase {

    @Mock
    private BlockLoader<RefCountedByteBuffer> mockLoader;

    private Cache<BlockCacheKey, BlockCacheValue<RefCountedByteBuffer>> caffeineCache;
    private CaffeineBlockCache<RefCountedByteBuffer, RefCountedByteBuffer> blockCache;

    /** Allocates a fresh GC-managed direct buffer wrapped in a RefCountedByteBuffer. */
    private static RefCountedByteBuffer block(int size) {
        return new RefCountedByteBuffer(ByteBuffer.allocateDirect(size), size);
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        MockitoAnnotations.openMocks(this);

        caffeineCache = Caffeine.newBuilder().maximumSize(100).removalListener((key, value, cause) -> {
            if (value != null) {
                ((BlockCacheValue<?>) value).close();
            }
        }).build();

        blockCache = new CaffeineBlockCache<>(caffeineCache, mockLoader, 100);
    }

    @After
    public void tearDown() throws Exception {
        if (caffeineCache != null) {
            caffeineCache.invalidateAll();
        }
        super.tearDown();
    }

    public void testGetReturnsNullForMissingKey() {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key = new FileBlockCacheKey(filePath, 0);

        BlockCacheValue<RefCountedByteBuffer> value = blockCache.get(key);

        assertNull(value);
    }

    public void testGetReturnsCachedValue() {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key = new FileBlockCacheKey(filePath, 0);

        RefCountedByteBuffer refSegment = block(1024);

        blockCache.put(key, refSegment);

        BlockCacheValue<RefCountedByteBuffer> retrieved = blockCache.get(key);

        assertNotNull(retrieved);
        assertEquals(refSegment, retrieved);
    }

    public void testGetOrLoadLoadsWhenMissing() throws IOException, Exception {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key = new FileBlockCacheKey(filePath, 0);

        RefCountedByteBuffer refSegment = block(1024);

        when(mockLoader.load(any(BlockCacheKey.class))).thenReturn(refSegment);

        BlockCacheValue<RefCountedByteBuffer> value = blockCache.getOrLoad(key);

        assertNotNull(value);
        assertEquals(refSegment, value);
        verify(mockLoader, times(1)).load(key);
    }

    public void testGetOrLoadReturnsCachedValue() throws IOException, Exception {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key = new FileBlockCacheKey(filePath, 0);

        RefCountedByteBuffer refSegment = block(1024);

        blockCache.put(key, refSegment);

        BlockCacheValue<RefCountedByteBuffer> value = blockCache.getOrLoad(key);

        assertNotNull(value);
        assertEquals(refSegment, value);
        verify(mockLoader, times(0)).load(key); // Should not load
    }

    public void testGetOrLoadThrowsOnLoadFailure() throws Exception {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key = new FileBlockCacheKey(filePath, 0);

        when(mockLoader.load(any(BlockCacheKey.class))).thenThrow(new RuntimeException("Load failed"));

        try {
            blockCache.getOrLoad(key);
            fail("Expected IOException");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Failed to load block"));
        }
    }

    public void testPut() {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key = new FileBlockCacheKey(filePath, 0);

        RefCountedByteBuffer refSegment = block(1024);

        blockCache.put(key, refSegment);

        BlockCacheValue<RefCountedByteBuffer> retrieved = blockCache.get(key);
        assertNotNull(retrieved);
        assertEquals(refSegment, retrieved);
    }

    public void testInvalidate() {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key = new FileBlockCacheKey(filePath, 0);

        RefCountedByteBuffer refSegment = block(1024);

        blockCache.put(key, refSegment);
        assertNotNull(blockCache.get(key));

        blockCache.invalidate(key);

        assertNull(blockCache.get(key));
    }

    public void testInvalidateByFilePath() {
        Path filePath = Paths.get("/test/file.txt");
        BlockCacheKey key1 = new FileBlockCacheKey(filePath, 0);
        BlockCacheKey key2 = new FileBlockCacheKey(filePath, 1);
        BlockCacheKey key3 = new FileBlockCacheKey(Paths.get("/test/other.txt"), 0);

        blockCache.put(key1, block(1024));
        blockCache.put(key2, block(1024));
        blockCache.put(key3, block(1024));

        blockCache.invalidate(filePath);

        assertNull(blockCache.get(key1));
        assertNull(blockCache.get(key2));
        assertNotNull(blockCache.get(key3)); // Different file, should remain
    }

    public void testInvalidateByPathPrefix() {
        Path indexPath = Paths.get("/data/indices/index1");
        Path shard0File = Paths.get("/data/indices/index1/0/index/segments.gen");
        Path shard1File = Paths.get("/data/indices/index1/1/index/segments.gen");
        Path otherIndexFile = Paths.get("/data/indices/index2/0/index/segments.gen");

        BlockCacheKey key1 = new FileBlockCacheKey(shard0File, 0);
        BlockCacheKey key2 = new FileBlockCacheKey(shard0File, 8192);
        BlockCacheKey key3 = new FileBlockCacheKey(shard1File, 0);
        BlockCacheKey key4 = new FileBlockCacheKey(otherIndexFile, 0);

        blockCache.put(key1, block(1024));
        blockCache.put(key2, block(1024));
        blockCache.put(key3, block(1024));
        blockCache.put(key4, block(1024));

        // Invalidate all entries under index1
        blockCache.invalidateByPathPrefix(indexPath);

        assertNull(blockCache.get(key1)); // index1/shard0 - should be removed
        assertNull(blockCache.get(key2)); // index1/shard0 - should be removed
        assertNull(blockCache.get(key3)); // index1/shard1 - should be removed
        assertNotNull(blockCache.get(key4)); // index2 - should remain
    }

    public void testClear() {
        Path filePath1 = Paths.get("/test/file1.txt");
        Path filePath2 = Paths.get("/test/file2.txt");
        BlockCacheKey key1 = new FileBlockCacheKey(filePath1, 0);
        BlockCacheKey key2 = new FileBlockCacheKey(filePath2, 0);

        blockCache.put(key1, block(1024));
        blockCache.put(key2, block(1024));

        blockCache.clear();

        assertNull(blockCache.get(key1));
        assertNull(blockCache.get(key2));
    }

    public void testCacheStats() {
        String stats = blockCache.cacheStats();

        assertNotNull(stats);
        assertTrue(stats.length() > 0);
    }

    public void testLoadBulk() throws IOException, Exception {
        Path filePath = Paths.get("/test/file.txt");
        long startOffset = 0;
        long blockCount = 3;

        RefCountedByteBuffer[] segments = new RefCountedByteBuffer[] { block(1024), block(1024), block(1024) };
        when(mockLoader.load(any(Path.class), any(Long.class), any(Long.class), anyLong())).thenReturn(segments);

        Map<BlockCacheKey, BlockCacheValue<RefCountedByteBuffer>> result = blockCache.loadForPrefetch(filePath, startOffset, blockCount);

        assertNotNull(result);
        assertEquals(3, result.size());
    }

    public void testMultipleCacheOperations() {
        Path filePath = Paths.get("/test/file.txt");

        // Add multiple blocks
        for (int i = 0; i < 10; i++) {
            BlockCacheKey key = new FileBlockCacheKey(filePath, i);
            blockCache.put(key, block(1024));
        }

        // Verify all are cached
        for (int i = 0; i < 10; i++) {
            BlockCacheKey key = new FileBlockCacheKey(filePath, i);
            assertNotNull(blockCache.get(key));
        }

        // Invalidate half
        for (int i = 0; i < 5; i++) {
            BlockCacheKey key = new FileBlockCacheKey(filePath, i);
            blockCache.invalidate(key);
        }

        // Verify invalidated
        for (int i = 0; i < 5; i++) {
            BlockCacheKey key = new FileBlockCacheKey(filePath, i);
            assertNull(blockCache.get(key));
        }

        // Verify remaining
        for (int i = 5; i < 10; i++) {
            BlockCacheKey key = new FileBlockCacheKey(filePath, i);
            assertNotNull(blockCache.get(key));
        }
    }

    public void testBlockCacheKeyEquality() {
        Path filePath1 = Paths.get("/test/file.txt");
        Path filePath2 = Paths.get("/test/file.txt");

        BlockCacheKey key1 = new FileBlockCacheKey(filePath1, 0);
        BlockCacheKey key2 = new FileBlockCacheKey(filePath2, 0);
        BlockCacheKey key3 = new FileBlockCacheKey(filePath1, 1);

        assertEquals(key1, key2);
        assertEquals(key1.hashCode(), key2.hashCode());
        assertTrue(!key1.equals(key3));
    }

    public void testCacheSizeLimit() throws Exception {
        // Create a small cache
        Cache<BlockCacheKey, BlockCacheValue<RefCountedByteBuffer>> smallCache = Caffeine
            .newBuilder()
            .maximumSize(5)
            .removalListener((key, value, cause) -> {
                if (value != null) {
                    ((BlockCacheValue<?>) value).close();
                }
            })
            .build();

        CaffeineBlockCache<RefCountedByteBuffer, RefCountedByteBuffer> smallBlockCache = new CaffeineBlockCache<>(
            smallCache,
            mockLoader,
            5
        );

        Path filePath = Paths.get("/test/file.txt");

        // Add more than cache size
        for (int i = 0; i < 10; i++) {
            BlockCacheKey key = new FileBlockCacheKey(filePath, i);
            smallBlockCache.put(key, block(1024));
        }

        // Force cache cleanup
        smallCache.cleanUp();

        // Cache should have evicted some entries
        long cacheSize = smallCache.estimatedSize();
        assertTrue(cacheSize <= 5);
    }
}
