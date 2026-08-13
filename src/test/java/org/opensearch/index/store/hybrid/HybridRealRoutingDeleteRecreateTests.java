/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.hybrid;

import java.nio.file.Path;
import java.util.Arrays;

import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.apache.lucene.tests.util.LuceneTestCase.AwaitsFix;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.CryptoTestDirectoryFactory;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Can the delete+recreate stale-cache bug be hit through the REAL HybridCryptoDirectory (production
 * routing)? Uses a ".doc" file — a BufferPool-routed extension — so the file genuinely goes through
 * the encrypted BufferPool read/write path (not the NIO path the extensionless contract files use).
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class HybridRealRoutingDeleteRecreateTests extends LuceneTestCase {

    // KNOWN GAP (documented reproduction): proves the stale-cache-on-recreate bug is reachable through
    // the REAL HybridCryptoDirectory (production routing) — not only the forced-BufferPool test mode.
    // A ".doc" file (BufferPool-routed) written, read, deleted, then recreated at the same path with new
    // content reads back the OLD (stale) bytes, because HybridCryptoDirectory.deleteFile routes to
    // NIOFS/super and skips BufferPoolDirectory's path-keyed cache invalidation. Rare in production
    // (unique segment names; rename already invalidates), so tracked rather than fixed on the delete
    // hot path (block-cache invalidation is O(blocks-of-file)). See HybridBufferPoolDirectoryBaseTests.
    @AwaitsFix(bugUrl = "https://github.com/opensearch-project/opensearch-storage-encryption/issues")
    public void testDeleteRecreateBufferPoolRoutedFile() throws Exception {
        Path p = createTempDir("realHybrid");
        try (Directory d = CryptoTestDirectoryFactory.createHybridCryptoDirectory(p, FSLockFactory.getDefault())) {
            final String name = "_0.doc"; // ".doc" is NOT a NIO extension -> routes to BufferPool

            byte[] v1 = new byte[4096];
            Arrays.fill(v1, (byte) 0xAA);
            writeBytes(d, name, v1);
            byte[] read1 = readAll(d, name); // populate the BufferPool caches for this path
            assertArrayEquals("v1 round-trip", v1, read1);

            d.deleteFile(name);

            byte[] v2 = new byte[4096];
            Arrays.fill(v2, (byte) 0x55); // different content at the SAME path
            writeBytes(d, name, v2);
            byte[] read2 = readAll(d, name);

            assertArrayEquals("STALE READ via real Hybrid on delete+recreate of a BufferPool-routed file", v2, read2);
        }
    }

    private static void writeBytes(Directory d, String name, byte[] data) throws Exception {
        try (IndexOutput out = d.createOutput(name, IOContext.DEFAULT)) {
            out.writeBytes(data, 0, data.length);
        }
    }

    private static byte[] readAll(Directory d, String name) throws Exception {
        try (IndexInput in = d.openInput(name, IOContext.DEFAULT)) {
            byte[] b = new byte[(int) in.length()];
            in.readBytes(b, 0, b.length);
            return b;
        }
    }
}
