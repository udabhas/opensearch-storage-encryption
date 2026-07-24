/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IndexOutput;
import org.opensearch.common.Randomness;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Drives {@link CryptoNIOFSDirectory#rename} directly (not the underlying cache) to guard the invalidation
 * contract: renaming must clear cached footer/frame-IV state for BOTH the source and destination paths, so a
 * path recreated/replaced by the move is never served the previous inode's metadata under the unauthenticated
 * AES-CTR read path. Removing either {@code invalidateFile} in the override fails this test.
 */
public class CryptoNIOFSDirectoryRenameTests extends OpenSearchTestCase {

    private static final byte[] MASTER_KEY = new byte[32];
    static {
        for (int i = 0; i < MASTER_KEY.length; i++) {
            MASTER_KEY[i] = (byte) (i + 1);
        }
    }

    private CryptoNIOFSDirectory newDirectory(Path dir, EncryptionMetadataCache cache) throws Exception {
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
        KeyResolver keyResolver = mock(KeyResolver.class);
        byte[] rawKey = new byte[32];
        Randomness.get().nextBytes(rawKey);
        when(keyResolver.getDataKey()).thenReturn(new SecretKeySpec(rawKey, "AES"));
        Provider provider = Security.getProvider("SunJCE");
        return new CryptoNIOFSDirectory(FSLockFactory.getDefault(), dir, provider, keyResolver, cache);
    }

    public void testRenameInvalidatesSourceAndDestInCache() throws Exception {
        Path dir = createTempDir();
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        CryptoNIOFSDirectory directory = newDirectory(dir, cache);

        String source = "source.tmp";
        String dest = "dest.si";

        // Create a real source file in the directory so rename has something to move.
        try (IndexOutput out = directory.createOutput(source, org.apache.lucene.store.IOContext.DEFAULT)) {
            out.writeBytes(randomByteArrayOfLength(64), 64);
        }

        String srcPath = EncryptionMetadataCache.normalizePath(dir.resolve(source));
        String dstPath = EncryptionMetadataCache.normalizePath(dir.resolve(dest));

        // Seed cache state for both paths (as prior writes/reads would have). Stamp with a NULL inode so the
        // read-side inode re-check can never prove staleness (matchesInode returns true) -> the entries can
        // ONLY be nulled by the rename override's invalidateFile calls, not by an incidental dropStale. This
        // makes both the source AND destination assertions true mutation guards: removing either
        // invalidateFile line in the override fails this test.
        byte[] srcMsgId = randomByteArrayOfLength(16);
        byte[] dstMsgId = randomByteArrayOfLength(16);
        cache.getOrLoadMetadata(srcPath, EncryptionFooter.generateNew(1L << 14, (short) 0), MASTER_KEY, null);
        cache.putFrameIv(srcPath, 0L, srcMsgId, randomByteArrayOfLength(16));
        cache.getOrLoadMetadata(dstPath, EncryptionFooter.generateNew(1L << 14, (short) 0), MASTER_KEY, null);
        cache.putFrameIv(dstPath, 0L, dstMsgId, randomByteArrayOfLength(16));

        directory.rename(source, dest);

        // Both paths' cached state must be gone after the rename override runs.
        assertNull("source footer must be invalidated by rename", cache.getFooter(srcPath));
        assertNull("source frame IV must be invalidated by rename", cache.getFrameIv(srcPath, 0L, srcMsgId));
        assertNull("dest footer must be invalidated by rename", cache.getFooter(dstPath));
        assertNull("dest frame IV must be invalidated by rename", cache.getFrameIv(dstPath, 0L, dstMsgId));

        directory.close();
    }
}
