/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.hamcrest.OpenSearchAssertions.assertAcked;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.indices.recovery.PeerRecoveryTargetService;
import org.opensearch.plugins.Plugin;
import org.opensearch.search.SearchHit;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.transport.MockTransportService;
import org.opensearch.transport.TransportService;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Interrupted / retried peer-recovery robustness for encrypted (cryptofs) indices.
 *
 * <p>Models the production blue/green failure mode where a peer recovery aborts mid-transfer, leaves partial
 * files on the target, and is retried. The retry must delete those leftovers and reconstruct the shard with
 * EXACT content — on the cryptofs delete-recreate path where {@code deleteFile} routes to NIOFS. This is a
 * robustness guard (correct content + clean recovery after a botched attempt), distinct from the cache-
 * coherence guards: a retried recovery re-downloads byte-identical immutable segment files, so the value here
 * is that interruption + orphan cleanup + re-download on cryptofs does not corrupt or lose data.
 *
 * <p>A replica build is used as the recovery vehicle because {@code ensureGreen} genuinely blocks until the
 * replica exists, which forces the retry to complete (a failed <em>relocation</em>, by contrast, leaves the
 * shard green on the source, so there is nothing to wait on).
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
public class CryptoInterruptedRecoveryIntegTests extends OpenSearchIntegTestCase {

    private static final int NUM_DOCS = 200;

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Arrays
            .asList(
                CryptoDirectoryPlugin.class,
                MockCryptoKeyProviderPlugin.class,
                MockCryptoPlugin.class,
                MockTransportService.TestPlugin.class
            );
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings
            .builder()
            .put(super.nodeSettings(nodeOrdinal))
            .put("plugins.crypto.enabled", true)
            .put("node.store.crypto.pool_size_percentage", 0.05)
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
            .put("index.number_of_shards", 1)
            .put("index.number_of_replicas", 0)
            .build();
    }

    private String copyHoldingNodeName(String index) {
        ClusterState state = client().admin().cluster().prepareState().get().getState();
        ShardRouting primary = state.routingTable().index(index).shard(0).primaryShard();
        return state.nodes().get(primary.currentNodeId()).getName();
    }

    private void assertAllDocsOnReplica(String index) {
        SearchResponse response = client()
            .prepareSearch(index)
            .setPreference("_replica")
            .setQuery(QueryBuilders.matchAllQuery())
            .setSize(NUM_DOCS)
            .get();
        assertThat(response.getHits().getTotalHits().value(), equalTo((long) NUM_DOCS));
        boolean[] seen = new boolean[NUM_DOCS];
        for (SearchHit hit : response.getHits().getHits()) {
            int i = Integer.parseInt(hit.getId());
            assertThat(
                "doc " + i + " stale/corrupt on replica after botched-recovery retry",
                hit.getSourceAsMap().get("field"),
                equalTo("value" + i)
            );
            seen[i] = true;
        }
        for (int i = 0; i < NUM_DOCS; i++) {
            assertThat("doc " + i + " missing from replica after botched-recovery retry", seen[i], is(true));
        }
    }

    // Content assertion against the primary copy with an explicit per-doc expected-value prefix.
    private void assertAllDocsPrimary(String index, String valuePrefix, String phase) {
        SearchResponse response = client()
            .prepareSearch(index)
            .setPreference("_primary")
            .setQuery(QueryBuilders.matchAllQuery())
            .setSize(NUM_DOCS)
            .get();
        assertThat("doc count " + phase, response.getHits().getTotalHits().value(), equalTo((long) NUM_DOCS));
        boolean[] seen = new boolean[NUM_DOCS];
        for (SearchHit hit : response.getHits().getHits()) {
            int i = Integer.parseInt(hit.getId());
            assertThat("doc " + i + " stale/corrupt on source primary " + phase, hit.getSourceAsMap().get("field"), equalTo(valuePrefix + i));
            seen[i] = true;
        }
        for (int i = 0; i < NUM_DOCS; i++) {
            assertThat("doc " + i + " missing from source primary " + phase, seen[i], is(true));
        }
    }

    private void assertPrimaryOnNode(String index, String expectedNode, String phase) {
        ClusterState state = client().admin().cluster().prepareState().get().getState();
        ShardRouting primary = state.routingTable().index(index).shard(0).primaryShard();
        String actual = state.nodes().get(primary.currentNodeId()).getName();
        assertThat("primary node " + phase, actual, equalTo(expectedNode));
    }

    /**
     * Q2 — source-side reads during an in-flight relocation. Pause a relocation A-&gt;B mid file-transfer (hold
     * the first FILE_CHUNK on a latch) so the SOURCE stays the live primary, then churn the source (force-merges
     * delete old segments; deleteFile-&gt;NIOFS leaves the stale L2/FD entries behind) and search the source after
     * each round. Every source-side search must return the exact current content. This exercises the source's
     * bufferpool read path concurrently with recovery reads, which routing did NOT change. Coherence here rests
     * on Lucene's monotonic segment naming (a merged-away name is never reused), so a stale read would only
     * appear if that guarantee broke — a per-doc value mismatch would catch it. Regression/coverage guard.
     */
    public void testSourceReadsCorrectContentDuringInFlightRelocation() throws Exception {
        internalCluster().startNodes(2);
        String[] nodes = internalCluster().getNodeNames();

        String index = "test-source-inflight";
        createIndex(
            index,
            Settings.builder().put(cryptoIndexSettings()).put("index.routing.allocation.require._name", nodes[0]).build()
        );
        ensureGreen(index);
        String source = copyHoldingNodeName(index);
        String target = source.equals(nodes[0]) ? nodes[1] : nodes[0];

        // gen-0 content, consolidated, and warm the source's caches.
        for (int i = 0; i < NUM_DOCS; i++) {
            index(index, "_doc", String.valueOf(i), "field", "v0-" + i, "number", i);
        }
        client().admin().indices().prepareRefresh(index).get();
        client().admin().indices().prepareFlush(index).get();
        client().admin().indices().prepareForceMerge(index).setMaxNumSegments(1).get();
        assertAllDocsPrimary(index, "v0-", "before relocation");

        // Hold the first recovery FILE_CHUNK on a latch so the relocation stays in-flight while we churn+read the
        // source. Blocking this recovery send does NOT block the source's search/index thread pools.
        MockTransportService sourceTransport = (MockTransportService) internalCluster().getInstance(TransportService.class, source);
        TransportService targetTransport = internalCluster().getInstance(TransportService.class, target);
        final CountDownLatch release = new CountDownLatch(1);
        final AtomicBoolean held = new AtomicBoolean(false);
        sourceTransport.addSendBehavior(targetTransport, (connection, requestId, action, request, options) -> {
            if (action.equals(PeerRecoveryTargetService.Actions.FILE_CHUNK) && held.compareAndSet(false, true)) {
                try {
                    release.await(60, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            connection.sendRequest(requestId, action, request, options);
        });

        try {
            // Start the relocation but do NOT wait for green; wait until a file chunk is actually being held.
            client()
                .admin()
                .indices()
                .prepareUpdateSettings(index)
                .setSettings(Settings.builder().put("index.routing.allocation.require._name", target))
                .get();
            assertBusy(() -> assertThat("recovery reached in-flight file transfer", held.get(), is(true)), 60, TimeUnit.SECONDS);

            // Source is still the live primary. Churn it (each round force-merges -> deletes old segments) and read
            // it back; the source must serve correct content throughout the in-flight window.
            for (int r = 1; r <= 3; r++) {
                for (int i = 0; i < NUM_DOCS; i++) {
                    index(index, "_doc", String.valueOf(i), "field", "r" + r + "-" + i, "number", i);
                }
                client().admin().indices().prepareRefresh(index).get();
                client().admin().indices().prepareForceMerge(index).setMaxNumSegments(1).get();
                assertPrimaryOnNode(index, source, "mid-flight round " + r + " (recovery must still be held)");
                assertAllDocsPrimary(index, "r" + r + "-", "mid-flight round " + r);
            }
        } finally {
            release.countDown();
            sourceTransport.clearAllRules();
        }

        // Let the relocation finish, then assert correct content on the relocated primary.
        ensureGreen(TimeValue.timeValueSeconds(120), index);
        assertPrimaryOnNode(index, target, "after relocation completes");
        for (int i = 0; i < NUM_DOCS; i++) {
            index(index, "_doc", String.valueOf(i), "field", "final-" + i, "number", i);
        }
        client().admin().indices().prepareRefresh(index).get();
        client().admin().indices().prepareForceMerge(index).setMaxNumSegments(1).get();
        assertAllDocsPrimary(index, "final-", "after relocation completes");
    }

    /**
     * Botch the first replica peer-recovery attempt (drop a file chunk mid-transfer, leaving partial files on
     * the target), let OpenSearch retry the build to completion, then assert the replica copy decrypts to the
     * exact indexed content.
     */
    public void testBotchedReplicaRecoveryRetryReadsCorrectContent() throws Exception {
        internalCluster().startNodes(2);

        String index = "test-botched-recovery";
        createIndex(index, cryptoIndexSettings());
        ensureGreen(index);

        for (int i = 0; i < NUM_DOCS; i++) {
            index(index, "_doc", String.valueOf(i), "field", "value" + i, "number", i);
        }
        client().admin().indices().prepareRefresh(index).get();
        client().admin().indices().prepareFlush(index).get();
        client().admin().indices().prepareForceMerge(index).setMaxNumSegments(1).get();

        // Source = the node holding the only copy; target = the other node (where the replica will be built).
        String[] nodes = internalCluster().getNodeNames();
        String sourceNode = copyHoldingNodeName(index);
        String targetNode = sourceNode.equals(nodes[0]) ? nodes[1] : nodes[0];

        // Inject a single failure on the SOURCE toward the TARGET: let the first file chunk through (real partial
        // bytes land on the target), then drop the second chunk ONCE. That aborts replica-recovery attempt #1
        // mid-transfer, leaving partial files on the target; OpenSearch then retries the build, which must succeed.
        MockTransportService sourceTransport = (MockTransportService) internalCluster().getInstance(TransportService.class, sourceNode);
        TransportService targetTransport = internalCluster().getInstance(TransportService.class, targetNode);
        final AtomicInteger chunkSeen = new AtomicInteger(0);
        final AtomicBoolean failedOnce = new AtomicBoolean(false);
        sourceTransport.addSendBehavior(targetTransport, (connection, requestId, action, request, options) -> {
            if (action.equals(PeerRecoveryTargetService.Actions.FILE_CHUNK)
                && chunkSeen.incrementAndGet() >= 2
                && failedOnce.compareAndSet(false, true)) {
                throw new IOException("Simulated botched recovery: dropped file chunk");
            }
            connection.sendRequest(requestId, action, request, options);
        });

        // Add a replica -> peer recovery builds it on the target. ensureGreen blocks until the replica is built,
        // so the botched attempt #1 must be retried to completion before this returns.
        try {
            assertAcked(
                client().admin().indices().prepareUpdateSettings(index).setSettings(Settings.builder().put("index.number_of_replicas", 1))
            );
            ensureGreen(TimeValue.timeValueSeconds(120), index);
        } finally {
            sourceTransport.clearAllRules();
        }

        // The botched attempt must have actually fired.
        assertThat("expected the injected chunk failure to fire (botched attempt occurred)", failedOnce.get(), is(true));

        // The retried replica must read the exact content — leftover partials from attempt #1 swept, no stale
        // or corrupt bytes on the cryptofs delete-recreate path.
        assertAllDocsOnReplica(index);
    }
}
