/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.index.store.cipher;

import org.opensearch.index.store.footer.EncryptionFooter;

import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cache for encryption metadata (footers and frame IVs) for an index.
 * Shared across all shards of the same index.
 * Lucene segment merging provides natural cleanup via deleteFile() calls.
 */
public class EncryptionMetadataCache {

    private static final class FooterKey {
        private final Path filePath;
        private final String pathString;
        private int hash;

        FooterKey(Path filePath) {
            this.filePath = filePath.toAbsolutePath().normalize();
            this.pathString = this.filePath.toString();
        }

        @Override
        public int hashCode() {
            int h = hash;
            if (h == 0) {
                h = pathString.hashCode();
                if (h == 0) h = 1;
                hash = h;
            }
            return h;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof FooterKey other)) return false;
            return pathString.equals(other.pathString);
        }
    }

    private static final class FrameKey {
        private final Path filePath;
        private final String pathString;
        private final long frameNumber;
        private int hash;

        FrameKey(Path filePath, long frameNumber) {
            this.filePath = filePath.toAbsolutePath().normalize();
            this.pathString = this.filePath.toString();
            this.frameNumber = frameNumber;
        }

        @Override
        public int hashCode() {
            int h = hash;
            if (h == 0) {
                h = 31 * pathString.hashCode() + Long.hashCode(frameNumber);
                if (h == 0) h = 1;
                hash = h;
            }
            return h;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof FrameKey other)) return false;
            return frameNumber == other.frameNumber && pathString.equals(other.pathString);
        }
    }

    private final ConcurrentHashMap<FooterKey, EncryptionFooter> footerCache;
    private final ConcurrentHashMap<FrameKey, byte[]> frameIvCache;

    public EncryptionMetadataCache() {
        this.footerCache = new ConcurrentHashMap<>(128, 0.75f, 4);
        this.frameIvCache = new ConcurrentHashMap<>(1024, 0.75f, 4);
    }

    public EncryptionFooter getFooter(Path filePath) {
        return footerCache.get(new FooterKey(filePath));
    }

    public void putFooter(Path filePath, EncryptionFooter footer) {
        footerCache.putIfAbsent(new FooterKey(filePath), footer);
    }

    public byte[] getFrameIv(Path filePath, long frameNumber) {
        return frameIvCache.get(new FrameKey(filePath, frameNumber));
    }

    public void putFrameIv(Path filePath, long frameNumber, byte[] iv) {
        frameIvCache.putIfAbsent(new FrameKey(filePath, frameNumber), iv);
    }

    public void invalidateFile(Path filePath) {
        String pathStr = filePath.toAbsolutePath().normalize().toString();
        footerCache.keySet().removeIf(key -> key.pathString.equals(pathStr));
        frameIvCache.keySet().removeIf(key -> key.pathString.equals(pathStr));
    }

    public void invalidateDirectory(Path directoryPath) {
        String dirPrefix = directoryPath.toAbsolutePath().normalize().toString();
        if (!dirPrefix.endsWith("/")) dirPrefix += "/";
        String finalPrefix = dirPrefix;
        footerCache.keySet().removeIf(key -> key.pathString.startsWith(finalPrefix));
        frameIvCache.keySet().removeIf(key -> key.pathString.startsWith(finalPrefix));
    }

    public void clear() {
        footerCache.clear();
        frameIvCache.clear();
    }
}
