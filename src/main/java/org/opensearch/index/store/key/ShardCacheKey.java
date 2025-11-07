/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.util.Objects;

/**
 * Immutable composite key for shard-level cache entries.
 * Combines index UUID and shard ID with optimized hashCode caching.
 * Shared across multiple shard-level registries for consistency.
 * 
 * <p>This key is used by:
 * <ul>
 * <li>EncryptionMetadataCacheRegistry - for EncryptionMetadataCache instances</li>
 * <li>NodeLevelKeyCache - for cached encryption keys</li>
 * </ul>
 * 
 * @opensearch.internal
 */
public final class ShardCacheKey {
    private final String indexUuid;
    private final int shardId;
    private int hash; // Lazy-computed cached hashCode

    /**
     * Creates a new shard cache key.
     * 
     * @param indexUuid the index UUID (must not be null)
     * @param shardId the shard ID
     */
    public ShardCacheKey(String indexUuid, int shardId) {
        this.indexUuid = Objects.requireNonNull(indexUuid, "indexUuid must not be null");
        this.shardId = shardId;
    }

    /**
     * Gets the index UUID.
     * 
     * @return the index UUID
     */
    public String getIndexUuid() {
        return indexUuid;
    }

    /**
     * Gets the shard ID.
     * 
     * @return the shard ID
     */
    public int getShardId() {
        return shardId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof ShardCacheKey))
            return false;
        ShardCacheKey that = (ShardCacheKey) o;
        return shardId == that.shardId && indexUuid.equals(that.indexUuid);
    }

    @Override
    public int hashCode() {
        int h = hash;
        if (h == 0) {
            h = Objects.hash(indexUuid, shardId);
            if (h == 0)
                h = 1; // Ensure non-zero for valid empty cache
            hash = h;
        }
        return h;
    }

    @Override
    public String toString() {
        return indexUuid + "-shard-" + shardId;
    }
}
