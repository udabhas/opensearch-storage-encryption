/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.nio.file.Files;
import java.nio.file.Path;

import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Regression: a path deleted and recreated at the same name maps to a NEW inode, but the metadata and
 * frame-IV caches key by path string. Pairing a stale footer/derived-key/frame-IV (old inode) with the new
 * inode's ciphertext would silently corrupt under unauthenticated AES-CTR. Each metadata entry is stamped with
 * the inode it was read from; a read that sees an inode mismatch drops the entry AND the path's frame IVs, so a
 * recreated path can never be served the previous inode's footer, key, or IV.
 *
 * <p>These tests exercise the drop-on-recreate path directly by driving the cache with explicit inode keys, so
 * they do not depend on the test filesystem producing distinguishable {@code fileKey()}s across a recreate.
 */
public class EncryptionMetadataCacheInodeTests extends OpenSearchTestCase {

    private static final byte[] MASTER_KEY = new byte[32];
    static {
        for (int i = 0; i < MASTER_KEY.length; i++) {
            MASTER_KEY[i] = (byte) (i + 1);
        }
    }

    /** Two distinct, non-null synthetic inode identities (independent of the test filesystem). */
    private static final Object INODE_A = "inode-A";
    private static final Object INODE_B = "inode-B";

    private static EncryptionFooter newFooter() {
        // frameSize/algorithmId values are irrelevant to the inode-keying behavior under test.
        return EncryptionFooter.generateNew(1L << 14, (short) 0);
    }

    /** A cached entry is served back for the SAME inode (baseline: no false invalidation). */
    public void testSameInodeServesCachedFooter() throws Exception {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        Path file = createTempFile();
        Files.write(file, randomByteArrayOfLength(64));
        String path = EncryptionMetadataCache.normalizePath(file);
        Object inode = EncryptionMetadataCache.inodeKey(file);

        EncryptionFooter footer = newFooter();
        cache.getOrLoadMetadata(path, footer, MASTER_KEY, inode);

        // Same inode -> the cached footer is returned (identity-equal to what we stored).
        assertSame(footer, cache.getFooter(path));
        assertNotNull(cache.getFileKey(path));
    }

    /**
     * Core assertion, driven with explicit inodes so it is deterministic on any filesystem: an entry
     * stamped with INODE_A must be dropped once the file's inode reads back as INODE_B.
     */
    public void testStaleInodeEntryIsDropped() throws Exception {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        Path file = createTempFile();
        Files.write(file, randomByteArrayOfLength(64));
        String path = EncryptionMetadataCache.normalizePath(file);

        // Stamp the entry with a KNOWN old inode that will never equal the file's real current inode.
        cache.getOrLoadMetadata(path, newFooter(), MASTER_KEY, INODE_A);
        // The file's real inode (whatever it is) differs from the synthetic INODE_A string, so the read-side
        // inode re-check fires and drops the stale entry.
        assertNull("stale-inode footer must be dropped", cache.getFooter(path));
        assertNull("stale-inode file key must be dropped", cache.getFileKey(path));
    }

    /**
     * The frame-IV cache must be purged together with the metadata entry on an inode mismatch (fix for the
     * gap where a stale, path-keyed frame IV outlived the dropped footer and corrupted the recreated inode's
     * reads).
     */
    public void testStaleInodeAlsoPurgesFrameIvs() throws Exception {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        Path file = createTempFile();
        Files.write(file, randomByteArrayOfLength(64));
        String path = EncryptionMetadataCache.normalizePath(file);

        // Cache a frame IV and a metadata entry stamped with a stale inode.
        byte[] messageId = randomByteArrayOfLength(16);
        byte[] oldIv = randomByteArrayOfLength(16);
        cache.putFrameIv(path, 0L, messageId, oldIv);
        cache.getOrLoadMetadata(path, newFooter(), MASTER_KEY, INODE_A);
        assertArrayEquals("precondition: frame IV cached", oldIv, cache.getFrameIv(path, 0L, messageId));

        // A read detects the inode mismatch (real inode != INODE_A) and must drop BOTH the metadata entry
        // and the path's frame IVs.
        assertNull(cache.getFooter(path));
        assertNull("stale frame IV must be purged on inode mismatch", cache.getFrameIv(path, 0L, messageId));
    }

    /**
     * Independent of the metadata-cache purge, a frame IV lookup keyed to a DIFFERENT messageId must miss, so
     * a recreated file (new footer -> new messageId) can never be served the previous inode's cached IV even
     * if no metadata entry existed to trigger the inode-mismatch drop.
     */
    public void testFrameIvBoundToMessageId() throws Exception {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        Path file = createTempFile();
        Files.write(file, randomByteArrayOfLength(64));
        String path = EncryptionMetadataCache.normalizePath(file);

        byte[] oldMessageId = randomByteArrayOfLength(16);
        byte[] newMessageId = randomByteArrayOfLength(16);
        byte[] oldIv = randomByteArrayOfLength(16);
        cache.putFrameIv(path, 0L, oldMessageId, oldIv);

        // Same messageId -> hit; different messageId -> miss (no stale IV reuse), no metadata entry involved.
        assertArrayEquals(oldIv, cache.getFrameIv(path, 0L, oldMessageId));
        assertNull("frame IV for a different messageId must not be served", cache.getFrameIv(path, 0L, newMessageId));

        // A put under the new messageId replaces the stale entry (not shadowed by putIfAbsent semantics).
        byte[] newIv = randomByteArrayOfLength(16);
        cache.putFrameIv(path, 0L, newMessageId, newIv);
        assertArrayEquals(newIv, cache.getFrameIv(path, 0L, newMessageId));
    }

    /** invalidateFile removes both the metadata entry and the frame IVs regardless of inode identity. */
    public void testInvalidateFileRemovesEntryAndFrameIvs() throws Exception {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        Path file = createTempFile();
        Files.write(file, randomByteArrayOfLength(64));
        String path = EncryptionMetadataCache.normalizePath(file);

        byte[] messageId = randomByteArrayOfLength(16);
        cache.getOrLoadMetadata(path, newFooter(), MASTER_KEY, EncryptionMetadataCache.inodeKey(file));
        cache.putFrameIv(path, 0L, messageId, randomByteArrayOfLength(16));
        assertNotNull(cache.getFooter(path));
        assertNotNull(cache.getFrameIv(path, 0L, messageId));

        cache.invalidateFile(path);
        assertNull(cache.getFooter(path));
        assertNull(cache.getFrameIv(path, 0L, messageId));
    }

    /** When inode identity is unavailable (null), the entry is retained (degrades to path-keyed semantics). */
    public void testNullInodeKeyRetainsEntry() throws Exception {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        Path file = createTempFile();
        Files.write(file, randomByteArrayOfLength(64));
        String path = EncryptionMetadataCache.normalizePath(file);

        // Stored with a null inode -> matchesInode() cannot prove staleness, so the entry survives reads.
        assertNotNull(cache.getOrLoadMetadata(path, newFooter(), MASTER_KEY, null));
        assertNotNull(cache.getFooter(path));
    }
}
