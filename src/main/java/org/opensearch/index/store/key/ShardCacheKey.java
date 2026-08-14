/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.util.Objects;

/**
 * Immutable composite key for shard-level cache entries.
 * Combines index UUID, shard ID, and index name with optimized hashCode caching.
 * Shared across multiple shard-level registries for consistency.
 * 
 * <p>The index name is stored for convenience (avoiding expensive cluster state lookups)
 * but is NOT part of the key identity - equals/hashCode use only UUID and shard ID.
 * 
 * <p>This key is used by:
 * <ul>
 * <li>ShardKeyResolverRegistry - for KeyResolver instances</li>
 * <li>EncryptionMetadataCacheRegistry - for EncryptionMetadataCache instances</li>
 * <li>NodeLevelKeyCache - for cached encryption keys</li>
 * </ul>
 * 
 * @opensearch.internal
 */
public final class ShardCacheKey {
    private final String indexUuid;
    private final int shardId;
    private final String indexName;
    // Node-scope discriminator: which node's copy of the shard this key belongs to. In production there is one
    // node per JVM so it is effectively always the local node (redundant). It matters for in-process multi-node
    // tests, where the resolver/key caches are JVM-static and would otherwise be shared — and cross-node
    // evicted — across nodes. null means "any node" (index-level lookups such as health checks).
    private final String nodeScope;
    private int hash; // Lazy-computed cached hashCode

    /**
     * Creates a new shard cache key.
     * 
     * @param indexUuid the index UUID (must not be null)
     * @param shardId the shard ID
     * @param indexName the index name (must not be null)
     */
    public ShardCacheKey(String indexUuid, int shardId, String indexName) {
        this(indexUuid, shardId, indexName, null);
    }

    public ShardCacheKey(String indexUuid, int shardId, String indexName, String nodeScope) {
        this.indexUuid = Objects.requireNonNull(indexUuid, "indexUuid must not be null");
        this.shardId = shardId;
        this.indexName = Objects.requireNonNull(indexName, "indexName must not be null");
        this.nodeScope = nodeScope;
    }

    /**
     * @return the node-scope discriminator (may be null for "any node" / index-level lookups)
     */
    public String getNodeScope() {
        return nodeScope;
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

    /**
     * Gets the index name.
     * 
     * @return the index name
     */
    public String getIndexName() {
        return indexName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof ShardCacheKey))
            return false;
        ShardCacheKey that = (ShardCacheKey) o;
        // Note: indexName is NOT part of key identity, only UUID + shardId (+ nodeScope for per-node isolation)
        return shardId == that.shardId && indexUuid.equals(that.indexUuid) && Objects.equals(nodeScope, that.nodeScope);
    }

    @Override
    public int hashCode() {
        int h = hash;
        if (h == 0) {
            // Note: indexName is NOT part of hashCode, only UUID + shardId (+ nodeScope for per-node isolation)
            h = Objects.hash(indexUuid, shardId, nodeScope);
            if (h == 0)
                h = 1; // Ensure non-zero for valid empty cache
            hash = h;
        }
        return h;
    }

    @Override
    public String toString() {
        return indexName + "(" + indexUuid + ")-shard-" + shardId + (nodeScope == null ? "" : "@" + nodeScope);
    }
}
