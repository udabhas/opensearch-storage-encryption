/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.index.store.cipher;

import org.opensearch.index.store.footer.EncryptionFooter;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Singleton cache for encryption metadata across all directories
 */
public class EncryptionCache {

    private static final EncryptionCache INSTANCE = new EncryptionCache();
    private static final String SEPARATOR = ":";

    private final ConcurrentHashMap<String, EncryptionFooter> footerCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, byte[]> frameIvCache = new ConcurrentHashMap<>();

    private EncryptionCache() {}

    public static EncryptionCache getInstance() {
        return INSTANCE;
    }

    public static String getCacheKey(String filePath, int frameNumber) {
        return filePath + SEPARATOR + frameNumber;
    }

    public Optional<EncryptionFooter> getFooter(String filePath) {
        return Optional.ofNullable(footerCache.get(filePath));
    }

    public void putFooter(String filePath, EncryptionFooter footer) {
        footerCache.putIfAbsent(filePath, footer);
    }

    public Optional<byte[]> getFrameIv(String filePath, int frameNumber) {
        return Optional.ofNullable(frameIvCache.get(getCacheKey(filePath, frameNumber)));
    }

    public void putFrameIv(String filePath, int frameNumber, byte[] iv) {
        frameIvCache.putIfAbsent(getCacheKey(filePath, frameNumber), iv);
    }

    public void invalidateFile(String filePath) {
        footerCache.remove(filePath);
        frameIvCache.keySet().removeIf(key -> key.startsWith(filePath + SEPARATOR));
    }

    public void clear() {
        footerCache.clear();
        frameIvCache.clear();
    }
}
