/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.hybrid;

import java.nio.file.Path;
import java.util.Arrays;

import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.CryptoTestDirectoryFactory;
import org.opensearch.index.store.CryptoTestDirectoryFactory.SharedCacheHybridPair;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Regression guard for THE Track-14 safety invariant: {@code BufferPoolDirectory.close()} MUST synchronously
 * prefix-invalidate the node-global block cache and FD cache.
 *
 * <p>Since {@code deleteFile} was routed to plain NIOFS (it no longer clears the path-keyed caches), the ONLY
 * thing that keeps a reused path coherent across a shard incarnation is {@code close()} running that
 * invalidation before the path is reused. The recovery integration tests can't catch a regression here —
 * Lucene's monotonic file naming means a recovered generation never reuses a warm-but-orphaned cached name,
 * so dropping the invalidation there only leaks memory, it doesn't serve stale bytes. This unit test forces
 * the reuse directly (two directories over the same path, sharing one node-global cache), so it goes RED the
 * moment {@code close()}'s invalidation is removed.
 *
 * <p>Sibling {@code HybridRealRoutingDeleteRecreateTests} proves the stale read WITHOUT a close in between
 * (the {@code @AwaitsFix} known gap); this test proves the close IS the mitigation.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class HybridCryptoDirectoryCloseInvalidationTests extends LuceneTestCase {

    /**
     * Warm incarnation #1's caches for a BufferPool-routed path, close it (as a departing shard would),
     * then delete+recreate the SAME path with new content on incarnation #2 (sharing the node-global cache).
     * The read MUST return the new content: close() invalidated the warm entries, so there is nothing stale
     * to serve. With close()'s prefix-invalidation removed, this read returns the OLD bytes and the test fails
     * — which is exactly the regression we want to catch.
     */
    public void testCloseInvalidatesCachesBeforePathReuse() throws Exception {
        Path p = createTempDir("closeInvalidation");
        try (SharedCacheHybridPair pair = CryptoTestDirectoryFactory.createSharedCacheHybridPair(p, FSLockFactory.getDefault())) {
            final String name = "_0.doc"; // ".doc" is NOT a NIO extension -> routes through the encrypting BufferPool

            // Incarnation #1: write v1 and read it back so the shared block cache + static FD cache are warm
            // for this path (the state a previously-hosting node is in before the shard leaves).
            byte[] v1 = new byte[4096];
            Arrays.fill(v1, (byte) 0xAA);
            writeBytes(pair.first, name, v1);
            assertArrayEquals("v1 round-trip on incarnation #1", v1, readAll(pair.first, name));

            // Shard leaves the node: the directory is closed. This is the ONLY cache invalidation on the path
            // now that deleteFile routes to NIOFS. Core guarantees this close happens-before any path reuse.
            pair.first.close();

            // Shard returns / new incarnation reuses the SAME path: delete (NIOFS, no invalidation) then recreate
            // with DIFFERENT content, mirroring a recovery that deletes+recreates a segment file at the same name.
            pair.second.deleteFile(name);
            byte[] v2 = new byte[4096];
            Arrays.fill(v2, (byte) 0x55);
            writeBytes(pair.second, name, v2);

            byte[] read2 = readAll(pair.second, name);
            assertArrayEquals("STALE READ after path reuse: close() must have prefix-invalidated the block + FD caches", v2, read2);
        }
    }

    private static void writeBytes(org.apache.lucene.store.Directory d, String name, byte[] data) throws Exception {
        try (IndexOutput out = d.createOutput(name, IOContext.DEFAULT)) {
            out.writeBytes(data, 0, data.length);
        }
    }

    private static byte[] readAll(org.apache.lucene.store.Directory d, String name) throws Exception {
        try (IndexInput in = d.openInput(name, IOContext.DEFAULT)) {
            byte[] b = new byte[(int) in.length()];
            in.readBytes(b, 0, b.length);
            return b;
        }
    }
}
