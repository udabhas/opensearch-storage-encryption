/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.security.Provider;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.opensearch.common.crypto.MasterKeyProvider;

/**
 * Registry that ensures only one KeyResolver instance exists per shard.
 * This prevents race conditions when multiple components try to create resolvers
 * for the same shard simultaneously.
 * 
 * <p>Uses shard-level granularity (indexUuid + shardId) for precise lifecycle management
 * and cache isolation between shards.
 * 
 * <p>Index-level locking ensures that when multiple shards of the same index are created
 * concurrently, only one thread initializes the shared index-level keyfile.
 *
 * @opensearch.internal
 */
public class ShardKeyResolverRegistry {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private ShardKeyResolverRegistry() {}

    private static final Logger logger = LogManager.getLogger(ShardKeyResolverRegistry.class);

    // Thread-safe cache of resolvers by shard
    private static final ConcurrentMap<ShardCacheKey, KeyResolver> resolverCache = new ConcurrentHashMap<>();

    // Index-level locks for keyfile initialization
    // Ensures that concurrent creation of multiple shards from the same index
    // doesn't result in race conditions when initializing the shared keyfile
    private static final ConcurrentMap<String, Object> indexInitLocks = new ConcurrentHashMap<>();

    /**
     * Gets or creates a KeyResolver for the specified shard.
     * If a resolver already exists for this shard, returns the existing instance.
     * Otherwise, creates a new resolver and caches it.
     * 
     * <p>This method is thread-safe and prevents race conditions during resolver creation.
     * Uses index-level locking to ensure that when multiple shards of the same index
     * are created concurrently, only one thread initializes the shared keyfile.
     *
     * @param indexUuid      the unique identifier for the index
     * @param indexDirectory the directory where encryption keys are stored
     * @param provider       the JCE provider for cryptographic operations
     * @param keyProvider    the master key provider
     * @param shardId        the shard ID
     * @return the KeyResolver instance for this shard
     * @throws RuntimeException if resolver creation fails
     */
    public static KeyResolver getOrCreateResolver(
        String indexUuid,
        Directory indexDirectory,
        Provider provider,
        MasterKeyProvider keyProvider,
        int shardId,
        String indexName
    ) {
        String nodeScope = nodeScopeOf(indexDirectory);
        ShardCacheKey key = new ShardCacheKey(indexUuid, shardId, indexName, nodeScope);

        // Get or create index-level lock object for this index
        // This ensures all shards of the same index synchronize on the same lock
        Object indexLock = indexInitLocks.computeIfAbsent(indexUuid, k -> new Object());

        // Synchronize at INDEX level to serialize keyfile initialization
        // This prevents race conditions when multiple shards are created concurrently
        synchronized (indexLock) {
            return resolverCache.computeIfAbsent(key, k -> {
                try {
                    return new DefaultKeyResolver(indexUuid, indexName, indexDirectory, provider, keyProvider, shardId, nodeScope);
                } catch (KeyCacheException e) {
                    // KeyCacheException already has clean, actionable error message - just rethrow
                    throw e;
                } catch (Exception e) {
                    // Unexpected error - wrap with context
                    throw new RuntimeException("Failed to create KeyResolver for shard: " + k, e);
                }
            });
        }
    }

    /**
     * Gets the cached resolver for the specified shard.
     *
     * @param indexUuid the unique identifier for the index
     * @param shardId   the shard ID
     * @param indexName the index name
     * @return the KeyResolver instance for this shard, or null if none exists
     */
    public static KeyResolver getResolver(String indexUuid, int shardId, String indexName) {
        return getResolver(indexUuid, shardId, indexName, null);
    }

    /**
     * Node-scoped resolver lookup. A null {@code nodeScope} means "any node" (index-level / health lookups)
     * and falls back to {@link #getAnyResolverForIndex}; a non-null scope does an exact per-node lookup so one
     * node's shard-close eviction cannot return another in-process node's resolver.
     *
     * @param indexUuid the index UUID
     * @param shardId   the shard ID
     * @param indexName the index name
     * @param nodeScope the node-scope discriminator, or null for any-node lookup
     * @return the resolver, or null if none matches
     */
    public static KeyResolver getResolver(String indexUuid, int shardId, String indexName, String nodeScope) {
        if (nodeScope == null) {
            return getAnyResolverForIndex(indexUuid);
        }
        return resolverCache.get(new ShardCacheKey(indexUuid, shardId, indexName, nodeScope));
    }

    /**
     * Derives a node-unique scope string from the index directory. In production there is one node per JVM so
     * this is effectively constant; across in-process test nodes the directory path differs per node, giving
     * per-node isolation of the JVM-static resolver/key caches.
     */
    private static String nodeScopeOf(Directory indexDirectory) {
        if (indexDirectory instanceof FSDirectory) {
            return ((FSDirectory) indexDirectory).getDirectory().toString();
        }
        return indexDirectory.toString();
    }

    /**
     * Removes the cached resolver for the specified shard.
     * This should be called when a shard is closed to prevent memory leaks.
     * Also evicts the key from the node-level cache.
     * Cleans up the index-level lock if this was the last shard for the index.
     *
     * @param indexUuid the unique identifier for the index
     * @param shardId   the shard ID
     * @param indexName the index name
     * @return the removed resolver, or null if no resolver was cached for this shard
     */
    public static KeyResolver removeResolver(String indexUuid, int shardId, String indexName, String nodeScope) {
        // Node-scoped: only remove THIS node's entry. A source node's shard-close must NOT evict another
        // in-process node's resolver/key — that was the cross-node "No resolver registered" race. In production
        // (one node per JVM) the node scope is the local node; across in-process test nodes it isolates them.
        // If the node scope is unknown (null), skip removal — a bounded, harmless leak — rather than risk a
        // cross-node evict.
        if (nodeScope == null) {
            return null;
        }
        ShardCacheKey key = new ShardCacheKey(indexUuid, shardId, indexName, nodeScope);

        // Lock-free by design: this runs on the cluster-applier thread, and getOrCreateResolver holds the
        // per-index lock across a synchronous KMS call. Taking that lock here could stall cluster-state
        // application for the full KMS duration. The map remove is atomic; a race with a concurrent
        // getOrCreateResolver only causes a harmless CACHE_MISS rebuild, never a wrong-key mint.
        // The per-index lock object is intentionally left in indexInitLocks (removing it risks a
        // lock-identity race); it is negligible memory.
        KeyResolver removed = resolverCache.remove(key);
        if (removed != null) {
            // Evict from node-level cache when shard is removed.
            try {
                NodeLevelKeyCache.getInstance().evict(indexUuid, shardId, indexName, nodeScope);
            } catch (IllegalStateException e) {
                logger.debug("Could not evict from NodeLevelKeyCache: {}", e.getMessage());
            }
        }
        return removed;
    }

    /**
     * Removes all cached resolvers for an index across every node scope, and evicts their node-level keys.
     * Used on index DELETE, which is cluster-wide, so clearing every scope's entry is correct.
     *
     * @param indexUuid the index UUID whose resolvers should be removed
     */
    public static void removeAllForIndex(String indexUuid) {
        for (ShardCacheKey key : new java.util.ArrayList<>(resolverCache.keySet())) {
            if (key.getIndexUuid().equals(indexUuid) && resolverCache.remove(key) != null) {
                try {
                    NodeLevelKeyCache.getInstance().evict(key.getIndexUuid(), key.getShardId(), key.getIndexName(), key.getNodeScope());
                } catch (IllegalStateException e) {
                    logger.debug("Could not evict from NodeLevelKeyCache: {}", e.getMessage());
                }
            }
        }
    }

    /**
     * Any-scope removal for the given shard (removes the (indexUuid, shardId) entry across every node scope).
     * Retained for tests/legacy callers; production shard-close uses the node-scoped
     * {@link #removeResolver(String, int, String, String)} to avoid evicting another node's entry.
     *
     * @return one of the removed resolvers, or null if none were cached
     */
    public static KeyResolver removeResolver(String indexUuid, int shardId, String indexName) {
        KeyResolver removed = null;
        for (ShardCacheKey k : new java.util.ArrayList<>(resolverCache.keySet())) {
            if (k.getIndexUuid().equals(indexUuid) && k.getShardId() == shardId) {
                KeyResolver r = resolverCache.remove(k);
                if (r != null) {
                    removed = r;
                    try {
                        NodeLevelKeyCache.getInstance().evict(k.getIndexUuid(), k.getShardId(), k.getIndexName(), k.getNodeScope());
                    } catch (IllegalStateException e) {
                        logger.debug("Could not evict from NodeLevelKeyCache: {}", e.getMessage());
                    }
                }
            }
        }
        return removed;
    }

    /**
     * Gets the number of cached resolvers.
     * Useful for monitoring and testing.
     *
     * @return the number of cached KeyResolver instances
     */
    public static int getCacheSize() {
        return resolverCache.size();
    }

    /**
     * Clears all cached resolvers and index-level locks.
     * This method is primarily for testing purposes.
     *
     * @return the number of resolvers that were removed
     */
    public static int clearCache() {
        int size = resolverCache.size();
        resolverCache.clear();
        indexInitLocks.clear();
        return size;
    }

    /**
     * Checks if a resolver is cached for the specified shard.
     *
     * @param indexUuid the unique identifier for the index
     * @param shardId   the shard ID
     * @param indexName the index name
     * @return true if a resolver is cached for this shard, false otherwise
     */
    public static boolean hasResolver(String indexUuid, int shardId, String indexName) {
        return resolverCache.containsKey(new ShardCacheKey(indexUuid, shardId, indexName));
    }

    /**
     * Gets any resolver for the specified index UUID that exists on this node.
     * Since all shards of an index share the same master key (stored at index level),
     * any shard's resolver can be used to check key availability.
     * 
     * This is useful for operations that need a resolver but don't know which
     * specific shards exist locally (e.g., health checks, key availability checks).
     * 
     * @param indexUuid the unique identifier for the index
     * @return any KeyResolver for this index, or null if no shards exist on this node
     */
    public static KeyResolver getAnyResolverForIndex(String indexUuid) {
        for (Map.Entry<ShardCacheKey, KeyResolver> entry : resolverCache.entrySet()) {
            if (entry.getKey().getIndexUuid().equals(indexUuid)) {
                return entry.getValue();  // Return first match - all shards share same master key
            }
        }
        return null;  // No shards for this index on this node
    }

    /**
     * Gets any shard ID for the specified index UUID that exists on this node.
     * Since all shards of an index share the same master key, any shard ID can be used
     * for cache lookups.
     * 
     * @param indexUuid the unique identifier for the index
     * @return any shard ID for this index, or -1 if no shards exist on this node
     */
    public static int getAnyShardIdForIndex(String indexUuid) {
        for (ShardCacheKey key : resolverCache.keySet()) {
            if (key.getIndexUuid().equals(indexUuid)) {
                return key.getShardId();  // Return first match - all shards share same master key
            }
        }
        return -1;  // No shards for this index on this node
    }

    /**
     * Gets all unique index UUIDs that have encrypted shards on this node.
     * This deduplicates the shard-level entries to return index-level UUIDs.
     * 
     * <p>This is the definitive list of encrypted indices on this node because:
     * <ul>
     *   <li>Only encrypted indices have resolvers</li>
     *   <li>Only shards on this node get registered</li>
     *   <li>The registry is the single source of truth</li>
     * </ul>
     * 
     * <p>Useful for proactive health checks and monitoring operations that need to
     * iterate over all encrypted indices present on this node.
     * 
     * @return a set of all unique index UUIDs with cached resolvers on this node
     */
    public static Set<String> getAllIndexUuids() {
        Set<String> indexUuids = new HashSet<>();
        for (ShardCacheKey key : resolverCache.keySet()) {
            indexUuids.add(key.getIndexUuid());
        }
        return indexUuids;
    }
}
