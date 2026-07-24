/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.key.HkdfKeyDerivation;

/**
 * Cache for encryption metadata (footers and frame IVs) for a directory.
 * Shared across all shards of the same index.
 * Lucene segment merging provides natural cleanup via deleteFile() calls.
 *
 * <p><b>Inode-aware keying (inode-aware):</b> entries are keyed by absolute path <em>string</em>, but a path can
 * be deleted and recreated at the same name (snapshot restore, recovery re-fetch, keyfile churn) so that the
 * name later maps to a <em>different</em> inode. Because the AES-CTR data read path is unauthenticated, pairing
 * a stale footer/derived-key (old inode) with the new inode's ciphertext would decrypt to silent garbage
 * (surfacing later as a Lucene CRC / CorruptIndexException), not fail fast. Each entry therefore records the
 * inode identity ({@link BasicFileAttributes#fileKey()}) captured when its footer was read, and every read
 * ({@link #getFooter}/{@link #getFileKey}) re-stats the path and drops the entry — <em>together with the
 * path's cached frame IVs</em> — if the inode no longer matches, so a recreated path can never be served the
 * previous inode's footer, derived key, or frame IVs.
 */
public class EncryptionMetadataCache {

    /**
     * Immutable container for file encryption metadata.
     * Thread-safe and ensures atomicity between footer and derived file key.
     */
    public static final class FileEncryptionMetadata {
        private final EncryptionFooter footer;
        private final byte[] fileKey;
        /** Inode identity ({@code fileKey()}) of the file the footer was read from; may be null if unavailable. */
        private final Object inodeKey;

        FileEncryptionMetadata(EncryptionFooter footer, byte[] masterKey, Object inodeKey) {
            this.footer = footer;
            this.fileKey = HkdfKeyDerivation.deriveFileKey(masterKey, footer.getMessageId());
            this.inodeKey = inodeKey;
        }

        public EncryptionFooter getFooter() {
            return footer;
        }

        public byte[] getFileKey() {
            return fileKey;
        }

        /** True if this entry was read from the same inode as {@code currentInodeKey} (or identity is unknown). */
        boolean matchesInode(Object currentInodeKey) {
            // If either side's inode identity is unavailable (fs without fileKey support, or a stat that failed),
            // we cannot prove staleness, so we do not drop the entry — behavior degrades to the pre-fix path-keyed
            // semantics on such filesystems rather than churning the cache.
            if (this.inodeKey == null || currentInodeKey == null) {
                return true;
            }
            return Objects.equals(this.inodeKey, currentInodeKey);
        }
    }

    /** A frame base IV together with the footer messageId it was derived from (identity-binds the entry). */
    private static final class CachedFrameIv {
        private final byte[] messageId;
        private final byte[] iv;

        CachedFrameIv(byte[] messageId, byte[] iv) {
            this.messageId = messageId;
            this.iv = iv;
        }
    }

    private final ConcurrentHashMap<String, FileEncryptionMetadata> fileMetadataCache;
    /**
     * Two-level frame IV cache: path → (frameNumber → CachedFrameIv). Nested layout gives O(1)
     * per-path invalidation via {@code frameIvCache.remove(path)}.
     */
    private final ConcurrentHashMap<String, ConcurrentHashMap<Long, CachedFrameIv>> frameIvCache;

    public EncryptionMetadataCache() {
        this.fileMetadataCache = new ConcurrentHashMap<>(128, 0.75f, 4);
        this.frameIvCache = new ConcurrentHashMap<>(1024, 0.75f, 4);
    }

    public static String normalizePath(Path filePath) {
        return filePath.toAbsolutePath().normalize().toString();
    }

    /**
     * Inode identity ({@link BasicFileAttributes#fileKey()}, i.e. dev+ino on Unix) for {@code path}, or
     * {@code null} if the file is gone or the filesystem does not expose a file key. Used to detect
     * delete-then-recreate-at-same-path so a stale footer is never paired with a new inode's ciphertext.
     */
    public static Object inodeKey(Path path) {
        try {
            return Files.readAttributes(path, BasicFileAttributes.class).fileKey();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Get or create file encryption metadata atomically.
     * If metadata doesn't exist, creates it from the provided footer and derives the file key.
     * Only one thread will perform the expensive HKDF derivation per file.
     *
     * <p>The inode identity is captured from the path here; prefer
     * {@link #getOrLoadMetadata(String, EncryptionFooter, byte[], Object)} from a read site that holds the
     * open channel, so the stored inode is guaranteed to pair with the footer that was read.
     *
     * @param normalizedPath normalized file path
     * @param footer the footer containing messageId for derivation
     * @param masterKey master key for deriving file key
     * @return file encryption metadata (cached or newly created)
     */
    public FileEncryptionMetadata getOrLoadMetadata(String normalizedPath, EncryptionFooter footer, byte[] masterKey) {
        return getOrLoadMetadata(normalizedPath, footer, masterKey, inodeKey(Paths.get(normalizedPath)));
    }

    /**
     * Get or create file encryption metadata atomically, stamping the entry with {@code inodeKey}.
     *
     * <p>Callers MUST pass the inode identity of the same file the {@code footer} was read from (capture it
     * right after opening the read channel). A stale entry for a recreated path is not overwritten here — it
     * is dropped on the next {@link #getFooter}/{@link #getFileKey} read via the inode re-check — so this only
     * inserts when absent and never persists a mismatched (footer, inode) pair from a racy caller.
     */
    public FileEncryptionMetadata getOrLoadMetadata(String normalizedPath, EncryptionFooter footer, byte[] masterKey, Object inodeKey) {
        return fileMetadataCache.computeIfAbsent(normalizedPath, k -> new FileEncryptionMetadata(footer, masterKey, inodeKey));
    }

    /**
     * Get cached footer, or null if not cached (or if the cached entry is for a stale inode, in which case the
     * entry is dropped so the caller re-reads the current inode's footer from disk).
     */
    public EncryptionFooter getFooter(String normalizedPath) {
        FileEncryptionMetadata metadata = fileMetadataCache.get(normalizedPath);
        if (metadata == null) {
            return null;
        }
        if (!metadata.matchesInode(inodeKey(Paths.get(normalizedPath)))) {
            // Path was recreated with a new inode; the cached footer/key AND frame IVs belong to the old
            // inode. Drop them all and force a fresh disk read for the current inode.
            dropStale(normalizedPath, metadata);
            return null;
        }
        return metadata.getFooter();
    }

    /**
     * Get cached file key, or null if not cached (or if the cached entry is for a stale inode — see
     * {@link #getFooter}).
     */
    public byte[] getFileKey(String normalizedPath) {
        FileEncryptionMetadata metadata = fileMetadataCache.get(normalizedPath);
        if (metadata == null) {
            return null;
        }
        if (!metadata.matchesInode(inodeKey(Paths.get(normalizedPath)))) {
            dropStale(normalizedPath, metadata);
            return null;
        }
        return metadata.getFileKey();
    }

    /**
     * Drops a stale-inode entry and the path's cached frame IVs. Removing the frame IVs is load-bearing: they
     * are keyed by path only and derived from the old inode's messageId, so leaving them would let a recreated
     * path decrypt with the wrong IV (silent AES-CTR corruption) even after the footer/key entry is gone. The
     * metadata entry is removed conditionally so a concurrent fresh insert for the new inode is not clobbered.
     */
    private void dropStale(String normalizedPath, FileEncryptionMetadata stale) {
        fileMetadataCache.remove(normalizedPath, stale);
        frameIvCache.remove(normalizedPath);
    }

    /**
     * Cached frame base IV for {@code (path, frameNumber)}, or {@code null} if absent OR if the cached IV
     * belongs to a different {@code messageId}. Binding the lookup to the footer's per-file random messageId
     * makes the frame-IV cache identity-safe on its own: a path recreated with a new inode carries a new
     * footer/messageId, so a stale IV can never be returned even if the metadata-cache purge did not run (the
     * frame-IV and metadata caches are populated independently). Returns a defensive copy.
     */
    public byte[] getFrameIv(String normalizedPath, long frameNumber, byte[] messageId) {
        ConcurrentHashMap<Long, CachedFrameIv> perFile = frameIvCache.get(normalizedPath);
        if (perFile == null) {
            return null;
        }
        CachedFrameIv cached = perFile.get(frameNumber);
        if (cached == null || !java.util.Arrays.equals(cached.messageId, messageId)) {
            return null;
        }
        return cached.iv.clone();
    }

    public void putFrameIv(String normalizedPath, long frameNumber, byte[] messageId, byte[] iv) {
        // computeIfAbsent-then-replace-on-messageId-change: overwrite a stale-messageId entry so a recreated
        // file's IV is not shadowed by the previous inode's (putIfAbsent alone would keep the old one).
        ConcurrentHashMap<Long, CachedFrameIv> perFile = frameIvCache
            .computeIfAbsent(normalizedPath, k -> new ConcurrentHashMap<>(2, 0.75f, 1));
        CachedFrameIv value = new CachedFrameIv(messageId.clone(), iv.clone());
        perFile.merge(frameNumber, value, (old, fresh) -> java.util.Arrays.equals(old.messageId, fresh.messageId) ? old : fresh);
    }

    public void invalidateFile(String normalizedPath) {
        fileMetadataCache.remove(normalizedPath);
        frameIvCache.remove(normalizedPath);
    }

    public void invalidateDirectory() {
        fileMetadataCache.clear();
        frameIvCache.clear();
    }
}
