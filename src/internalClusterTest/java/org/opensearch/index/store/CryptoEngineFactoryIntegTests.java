/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;

import java.util.Arrays;
import java.util.Collection;

import org.opensearch.action.admin.indices.stats.IndicesStatsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Integration tests for CryptoEngineFactory verifying that cryptofs indices
 * use crypto-enabled translogs for both primary and replica shards.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class CryptoEngineFactoryIntegTests extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Arrays.asList(CryptoDirectoryPlugin.class, MockCryptoKeyProviderPlugin.class, MockCryptoPlugin.class);
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings
            .builder()
            .put(super.nodeSettings(nodeOrdinal))
            .put("plugins.crypto.enabled", true)
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .put("node.store.crypto.warmup_percentage", 0.0)
            .put("node.store.crypto.cache_to_pool_ratio", 0.8)
            .put("node.store.crypto.key_refresh_interval", "30s")
            .build();
    }

    @Override
    protected boolean addMockInternalEngine() {
        return false;
    }

    private Settings cryptoIndexSettings() {
        return Settings
            .builder()
            .put("index.store.type", "cryptofs")
            .put("index.store.crypto.key_provider", "dummy")
            .put("index.store.crypto.kms.key_arn", "dummyArn")
            .build();
    }

    /**
     * Tests that CryptoEngineFactory creates InternalEngine for primary shards
     * with encrypted translog. Verified by writing data, restarting the node
     * (forcing translog recovery), and confirming all data is recovered.
     */
    public void testPrimaryShardWithEncryptedTranslog() throws Exception {
        internalCluster().startNode();

        Settings settings = Settings
            .builder()
            .put(cryptoIndexSettings())
            .put("index.number_of_shards", 1)
            .put("index.number_of_replicas", 0)
            .put("index.translog.flush_threshold_size", "1gb")
            .put("index.refresh_interval", "-1")
            .build();

        createIndex("test-primary", settings);
        ensureGreen("test-primary");

        int numDocs = randomIntBetween(50, 100);
        for (int i = 0; i < numDocs; i++) {
            index("test-primary", "_doc", String.valueOf(i), "field", "value" + i);
        }

        // Verify translog has uncommitted ops
        IndicesStatsResponse stats = client().admin().indices().prepareStats("test-primary").get();
        assertThat(stats.getIndex("test-primary").getTotal().getTranslog().getUncommittedOperations(), greaterThan(0));

        // Restart node to force translog recovery through CryptoTranslog
        internalCluster().fullRestart();
        ensureGreen("test-primary");
        refresh("test-primary");

        SearchResponse response = client().prepareSearch("test-primary").setSize(0).get();
        assertThat(
            "All docs should be recovered from encrypted translog",
            response.getHits().getTotalHits().value(),
            equalTo((long) numDocs)
        );

        flush("test-primary");
    }

    /**
     * Tests that CryptoEngineFactory creates NRTReplicationEngine for read-only
     * replica shards with segment replication enabled.
     */
    public void testReplicaShardWithSegmentReplication() throws Exception {
        internalCluster().startNodes(2);

        Settings settings = Settings
            .builder()
            .put(cryptoIndexSettings())
            .put("index.number_of_shards", 1)
            .put("index.number_of_replicas", 1)
            .put("index.replication.type", "SEGMENT")
            .build();

        createIndex("test-replica", settings);
        ensureGreen("test-replica");

        int numDocs = randomIntBetween(50, 100);
        for (int i = 0; i < numDocs; i++) {
            index("test-replica", "_doc", String.valueOf(i), "field", "value" + i);
        }
        refresh("test-replica");

        // Verify both primary and replica serve the data
        SearchResponse response = client().prepareSearch("test-replica").setSize(0).get();
        assertThat(response.getHits().getTotalHits().value(), equalTo((long) numDocs));

        // Verify via shard stats that replica has same doc count as primary
        IndicesStatsResponse stats = client().admin().indices().prepareStats("test-replica").get();
        assertThat("Should have primary + replica", stats.getShards().length, equalTo(2));

        long primaryDocs = -1;
        long replicaDocs = -1;
        for (var shardStats : stats.getShards()) {
            long docs = shardStats.getStats().getDocs().getCount();
            if (shardStats.getShardRouting().primary()) {
                primaryDocs = docs;
            } else {
                replicaDocs = docs;
            }
        }
        assertThat("Primary should have all docs", primaryDocs, equalTo((long) numDocs));
        assertThat("Replica should have same docs as primary", replicaDocs, equalTo(primaryDocs));

        flush("test-replica");
    }

    /**
     * Tests that CryptoEngineFactory handles the non-RemoteBlobStoreInternalTranslogFactory
     * fallback path by verifying a cryptofs index works with default translog settings.
     */
    public void testPrimaryShardWithDefaultTranslogFactory() throws Exception {
        internalCluster().startNode();

        Settings settings = Settings
            .builder()
            .put(cryptoIndexSettings())
            .put("index.number_of_shards", 1)
            .put("index.number_of_replicas", 0)
            .build();

        createIndex("test-default-translog", settings);
        ensureGreen("test-default-translog");

        int numDocs = randomIntBetween(10, 50);
        for (int i = 0; i < numDocs; i++) {
            index("test-default-translog", "_doc", String.valueOf(i), "field", "value" + i);
        }
        flush("test-default-translog");
        refresh("test-default-translog");

        SearchResponse response = client().prepareSearch("test-default-translog").setSize(0).get();
        assertThat(response.getHits().getTotalHits().value(), equalTo((long) numDocs));
    }
}
