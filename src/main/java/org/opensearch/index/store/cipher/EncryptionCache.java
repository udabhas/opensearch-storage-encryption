/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

//package org.opensearch.index.store.cipher;
//
//import org.opensearch.index.store.footer.EncryptionFooter;
//
//import java.util.Optional;
//import java.util.concurrent.ConcurrentHashMap;
//
///**
// * Singleton cache for encryption metadata across all directories
// */
//public class EncryptionCache {
//
//    private static final EncryptionCache INSTANCE = new EncryptionCache();
//    private static final String SEPARATOR = ":";
//
//    private final ConcurrentHashMap<String, EncryptionFooter> footerCache = new ConcurrentHashMap<>();
//    private final ConcurrentHashMap<String, byte[]> frameIvCache = new ConcurrentHashMap<>();
//
//    private EncryptionCache() {}
//
//    public static EncryptionCache getInstance() {
//        return INSTANCE;
//    }
//
//    public static String getCacheKey(String filePath, int frameNumber) {
//        return filePath + SEPARATOR + frameNumber;
//    }
//
//    public Optional<EncryptionFooter> getFooter(String filePath) {
//        return Optional.ofNullable(footerCache.get(filePath));
//    }
//
//    public void putFooter(String filePath, EncryptionFooter footer) {
//        footerCache.putIfAbsent(filePath, footer);
//    }
//
//    public Optional<byte[]> getFrameIv(String filePath, int frameNumber) {
//        return Optional.ofNullable(frameIvCache.get(getCacheKey(filePath, frameNumber)));
//    }
//
//    public void putFrameIv(String filePath, int frameNumber, byte[] iv) {
//        frameIvCache.putIfAbsent(getCacheKey(filePath, frameNumber), iv);
//    }
//
//    public void invalidateFile(String filePath) {
//        footerCache.remove(filePath);
//        frameIvCache.keySet().removeIf(key -> key.startsWith(filePath + SEPARATOR));
//    }
//
//    public void invalidateDirectory(String directoryPath) {
//        String dirPrefix = directoryPath.endsWith("/") ? directoryPath : directoryPath + "/";
//        footerCache.keySet().removeIf(key -> key.startsWith(dirPrefix));
//        frameIvCache.keySet().removeIf(key -> key.startsWith(dirPrefix));
//    }
//
//    public void clear() {
//        footerCache.clear();
//        frameIvCache.clear();
//    }
//}
package org.opensearch.index.store.cipher;

import org.opensearch.index.store.footer.EncryptionFooter;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class EncryptionCache {
    private static final EncryptionCache INSTANCE = new EncryptionCache();
    private static final String SEPARATOR = ":";
    private static final int MAX_FOOTER_ENTRIES = 1000;  // Bound cache size
    private static final int MAX_IV_ENTRIES = 10000;     // Bound cache size

    private final Cache<String, EncryptionFooter> footerCache;
    private final Cache<String, byte[]> frameIvCache;

    private EncryptionCache() {
        this.footerCache = Caffeine.newBuilder()
                .maximumSize(MAX_FOOTER_ENTRIES)
                .expireAfterAccess(1, TimeUnit.HOURS)  // Optional: expire unused entries
                .build();

        this.frameIvCache = Caffeine.newBuilder()
                .maximumSize(MAX_IV_ENTRIES)
                .expireAfterAccess(30, TimeUnit.MINUTES)
                .build();
    }

    public static EncryptionCache getInstance() {
        return INSTANCE;
    }

    public static String getCacheKey(String filePath, int frameNumber) {
        return filePath + SEPARATOR + frameNumber;
    }

    public Optional<EncryptionFooter> getFooter(String filePath) {
        return Optional.ofNullable(footerCache.getIfPresent(filePath));
    }

    public void putFooter(String filePath, EncryptionFooter footer) {
        footerCache.put(filePath, footer);
    }

    public Optional<byte[]> getFrameIv(String filePath, int frameNumber) {
        return Optional.ofNullable(frameIvCache.getIfPresent(getCacheKey(filePath, frameNumber)));
    }

    public void putFrameIv(String filePath, int frameNumber, byte[] iv) {
        frameIvCache.put(getCacheKey(filePath, frameNumber), iv);
    }

    public void invalidateFile(String filePath) {
        footerCache.invalidate(filePath);
        frameIvCache.asMap().keySet().removeIf(key -> key.startsWith(filePath + SEPARATOR));
    }

    public void invalidateDirectory(String directoryPath) {
        String dirPrefix = directoryPath.endsWith("/") ? directoryPath : directoryPath + "/";
        footerCache.asMap().keySet().removeIf(key -> key.startsWith(dirPrefix));
        frameIvCache.asMap().keySet().removeIf(key -> key.startsWith(dirPrefix));
    }

    public void clear() {
        footerCache.invalidateAll();
        frameIvCache.invalidateAll();
    }
}
