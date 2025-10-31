/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.index.store.cipher;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Registry that ensures only one EncryptionMetadataCache instance exists per index UUID.
 * Mirrors the pattern used by IndexKeyResolverRegistry for consistent architecture.
 * 
 * @opensearch.internal
 */
public class EncryptionMetadataCacheRegistry {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private EncryptionMetadataCacheRegistry() {}

    private static final ConcurrentMap<String, EncryptionMetadataCache> cacheRegistry = new ConcurrentHashMap<>();

    /**
     * Gets or creates an EncryptionMetadataCache for the specified index UUID.
     * If a cache already exists for this index, returns the existing instance.
     * Otherwise, creates a new cache and caches it.
     * 
     * This method is thread-safe and prevents race conditions during cache creation.
     * 
     * @param indexUuid the unique identifier for the index
     * @return the EncryptionMetadataCache instance for this index
     */
    public static EncryptionMetadataCache getOrCreateCache(String indexUuid) {
        return cacheRegistry.computeIfAbsent(indexUuid, uuid -> new EncryptionMetadataCache());
    }

    /**
     * Removes the cached EncryptionMetadataCache for the specified index UUID.
     * This should be called when an index is deleted to prevent memory leaks.
     * 
     * @param indexUuid the unique identifier for the index
     * @return the removed cache, or null if no cache was registered for this index
     */
    public static EncryptionMetadataCache removeCache(String indexUuid) {
        return cacheRegistry.remove(indexUuid);
    }

    /**
     * Gets the number of cached instances.
     * Useful for monitoring and testing.
     * 
     * @return the number of cached EncryptionMetadataCache instances
     */
    public static int getCacheSize() {
        return cacheRegistry.size();
    }

    /**
     * Clears all cached instances.
     * This method is primarily for testing purposes.
     */
    public static void clearAll() {
        cacheRegistry.clear();
    }

    /**
     * Checks if a cache is registered for the specified index UUID.
     * 
     * @param indexUuid the unique identifier for the index
     * @return true if a cache is registered for this index, false otherwise
     */
    public static boolean hasCache(String indexUuid) {
        return cacheRegistry.containsKey(indexUuid);
    }
}
