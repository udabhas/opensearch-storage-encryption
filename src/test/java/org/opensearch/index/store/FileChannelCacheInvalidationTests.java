/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.opensearch.test.OpenSearchTestCase;

import com.github.benmanes.caffeine.cache.Cache;

/**
 * Tests the node-global read-{@link FileChannel} cache invalidation contract in
 * {@link CryptoDirectoryFactory}.
 *
 * <p>The cache is keyed by absolute path; if a cached channel is not dropped when its file is
 * deleted/recreated at the same path, a later read would serve the OLD inode's ciphertext through
 * the stale FD while the footer/file-key is re-read from the NEW inode. Because the data read path
 * is unauthenticated AES-CTR, that produces silent garbage rather than a fast failure — so the
 * invalidation methods exercised here are safety-critical, not just hygiene.
 */
public class FileChannelCacheInvalidationTests extends OpenSearchTestCase {

    /** The producer (FileChannelBackend) and the invalidation consumers must agree on the key format. */
    public void testCacheKeyFormatIsStableAndAbsolute() throws Exception {
        Path dir = createTempDir();
        Path file = dir.resolve("seg.cfs");
        String key = CryptoDirectoryFactory.fileChannelCacheKey(file);
        assertEquals("dio:" + file.toAbsolutePath().normalize().toString(), key);

        // A relative vs absolute path to the same file must produce the same key (normalization).
        Path relativeStyle = dir.resolve("./seg.cfs");
        assertEquals(key, CryptoDirectoryFactory.fileChannelCacheKey(relativeStyle));
    }

    public void testInvalidateFileChannelDropsAndClosesTheCachedChannel() throws Exception {
        Path dir = createTempDir();
        Path file = Files.createFile(dir.resolve("seg.cfs"));

        Cache<String, FileChannel> cache = CryptoDirectoryFactory.getOrCreateFileChannelCache();
        String key = CryptoDirectoryFactory.fileChannelCacheKey(file);

        FileChannel ch = FileChannel.open(file, StandardOpenOption.READ);
        cache.put(key, ch);
        assertTrue("channel should start open", ch.isOpen());
        assertNotNull("entry should be cached", cache.getIfPresent(key));

        CryptoDirectoryFactory.invalidateFileChannel(file);
        cache.cleanUp(); // trigger pending maintenance

        assertNull("cached entry must be gone after invalidate", cache.getIfPresent(key));
        // Caffeine's removal listener runs asynchronously on the common ForkJoinPool by default,
        // so poll for close instead of asserting eagerly (occasional flake otherwise).
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2);
        while (ch.isOpen() && System.nanoTime() < deadline) {
            Thread.sleep(10);
            cache.cleanUp();
        }
        assertFalse("removal listener must CLOSE the evicted channel (no FD leak)", ch.isOpen());
    }

    public void testInvalidateByPrefixDropsOnlyMatchingDirectoryAndNotSiblings() throws Exception {
        Path base = createTempDir();
        Path indexDir = Files.createDirectories(base.resolve("index"));
        Path siblingDir = Files.createDirectories(base.resolve("index2")); // must NOT be matched by "index" prefix

        Path inIndex = Files.createFile(indexDir.resolve("a.cfs"));
        Path inSibling = Files.createFile(siblingDir.resolve("b.cfs"));

        Cache<String, FileChannel> cache = CryptoDirectoryFactory.getOrCreateFileChannelCache();
        String keyIn = CryptoDirectoryFactory.fileChannelCacheKey(inIndex);
        String keySibling = CryptoDirectoryFactory.fileChannelCacheKey(inSibling);

        FileChannel chIn = FileChannel.open(inIndex, StandardOpenOption.READ);
        FileChannel chSibling = FileChannel.open(inSibling, StandardOpenOption.READ);
        cache.put(keyIn, chIn);
        cache.put(keySibling, chSibling);

        CryptoDirectoryFactory.invalidateFileChannelsByPrefix(indexDir);
        cache.cleanUp();

        assertNull("file under the invalidated directory must be dropped", cache.getIfPresent(keyIn));
        // Caffeine's removal listener runs asynchronously on the common ForkJoinPool by default,
        // so poll for close instead of asserting eagerly (occasional flake otherwise).
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2);
        while (chIn.isOpen() && System.nanoTime() < deadline) {
            Thread.sleep(10);
            cache.cleanUp();
        }
        assertFalse("its channel must be closed", chIn.isOpen());

        assertNotNull("sibling directory 'index2' must NOT be matched by 'index' prefix", cache.getIfPresent(keySibling));
        assertTrue("sibling channel must stay open", chSibling.isOpen());

        // cleanup
        CryptoDirectoryFactory.invalidateFileChannelsByPrefix(siblingDir);
    }
}
