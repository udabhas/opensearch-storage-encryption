/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;

import org.opensearch.index.store.footer.EncryptionFooter;

/**
 * Cache for encryption metadata (footers and frame IVs) for an index.
 * Shared across all shards of the same index.
 * Lucene segment merging provides natural cleanup via deleteFile() calls.
 */
public class EncryptionMetadataCache {

    private static final class FrameKey {
        private final String pathString;
        private final long frameNumber;
        private int hash;

        FrameKey(String pathString, long frameNumber) {
            this.pathString = pathString;
            this.frameNumber = frameNumber;
        }

        @Override
        public int hashCode() {
            int h = hash;
            if (h == 0) {
                h = 31 * pathString.hashCode() + Long.hashCode(frameNumber);
                if (h == 0)
                    h = 1;
                hash = h;
            }
            return h;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (!(obj instanceof FrameKey other))
                return false;
            return frameNumber == other.frameNumber && pathString.equals(other.pathString);
        }
    }

    private final ConcurrentHashMap<String, EncryptionFooter> footerCache;
    private final ConcurrentHashMap<FrameKey, byte[]> frameIvCache;

    public EncryptionMetadataCache() {
        this.footerCache = new ConcurrentHashMap<>(128, 0.75f, 4);
        this.frameIvCache = new ConcurrentHashMap<>(1024, 0.75f, 4);
    }

    public static String normalizePath(Path filePath) {
        return filePath.toAbsolutePath().normalize().toString();
    }

    public EncryptionFooter getFooter(String normalizedPath) {
        return footerCache.get(normalizedPath);
    }

    public void putFooter(String normalizedPath, EncryptionFooter footer) {
        footerCache.putIfAbsent(normalizedPath, footer);
    }

    public byte[] getFrameIv(String normalizedPath, long frameNumber) {
        return frameIvCache.get(new FrameKey(normalizedPath, frameNumber));
    }

    public void putFrameIv(String normalizedPath, long frameNumber, byte[] iv) {
        frameIvCache.putIfAbsent(new FrameKey(normalizedPath, frameNumber), iv);
    }

    public void invalidateFile(String normalizedPath) {
        footerCache.remove(normalizedPath);
        frameIvCache.keySet().removeIf(key -> key.pathString.equals(normalizedPath));
    }

    public void invalidateDirectory(String normalizedDirPath) {
        String dirPrefix = normalizedDirPath.endsWith("/") ? normalizedDirPath : normalizedDirPath + "/";
        footerCache.keySet().removeIf(key -> key.startsWith(dirPrefix));
        frameIvCache.keySet().removeIf(key -> key.pathString.startsWith(dirPrefix));
    }

    public void clear() {
        footerCache.clear();
        frameIvCache.clear();
    }
}
