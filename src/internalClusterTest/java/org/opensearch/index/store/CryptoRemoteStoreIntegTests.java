/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.lucene.tests.util.LuceneTestCase.SuppressFileSystems;
import org.opensearch.action.admin.indices.stats.IndicesStatsResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.plugins.Plugin;
import org.opensearch.remotestore.RemoteStoreBaseIntegTestCase;
import org.opensearch.test.OpenSearchIntegTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Integration tests for CryptoEngineFactory with remote-store enabled.
 * Verifies that encrypted indices work correctly with remote segment and translog storage.
 *
 * Note: LeakFS is suppressed because CryptoRemoteFsTranslog has a known file handle leak
 * during shutdown with remote store enabled (many translog generations remain open).
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
@SuppressFileSystems("LeakFS")
public class CryptoRemoteStoreIntegTests extends RemoteStoreBaseIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Stream
            .concat(
                super.nodePlugins().stream(),
                Stream.of(CryptoDirectoryPlugin.class, MockCryptoKeyProviderPlugin.class, MockCryptoPlugin.class)
            )
            .collect(Collectors.toList());
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
     * Basic test: create an encrypted index with remote store enabled,
     * index docs, and verify replication to replica via shard stats.
     */
    public void testCryptoIndexWithRemoteStore() throws Exception {
        internalCluster().startNodes(2);

        Settings settings = Settings
            .builder()
            .put(cryptoIndexSettings())
            .put("index.number_of_shards", 1)
            .put("index.number_of_replicas", 1)
            .build();

        createIndex("test-crypto-rs", settings);
        ensureGreen("test-crypto-rs");

        int numDocs = randomIntBetween(20, 50);
        for (int i = 0; i < numDocs; i++) {
            index("test-crypto-rs", "_doc", String.valueOf(i), "field", "value" + i);
        }
        refresh("test-crypto-rs");

        // Wait for replica to catch up via remote store segment replication
        final int expectedDocs = numDocs;
        assertBusy(() -> {
            IndicesStatsResponse stats = client().admin().indices().prepareStats("test-crypto-rs").get();
            assertThat("Should have primary + replica", stats.getShards().length, equalTo(2));
            for (var shardStats : stats.getShards()) {
                assertThat(
                    "Shard [" + shardStats.getShardRouting() + "] should have all docs",
                    shardStats.getStats().getDocs().getCount(),
                    equalTo((long) expectedDocs)
                );
            }
        });

        // Verify remote store stats show successful uploads from primary
        var remoteStoreStats = client().admin().cluster().prepareRemoteStoreStats("test-crypto-rs", "0").get();
        for (var remoteShard : remoteStoreStats.getRemoteStoreStats()) {
            if (remoteShard.getShardRouting().primary()) {
                assertThat(
                    "Primary should have successful segment uploads",
                    remoteShard.getSegmentStats().totalUploadsStarted,
                    greaterThan(0L)
                );
            } else {
                assertThat(
                    "Replica should have successful segment downloads",
                    remoteShard.getSegmentStats().directoryFileTransferTrackerStats.transferredBytesStarted,
                    greaterThan(0L)
                );
            }
        }

        flush("test-crypto-rs");
        client().admin().indices().prepareDelete("test-crypto-rs").get();
    }
}
