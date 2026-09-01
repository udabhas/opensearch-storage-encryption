/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.common.Booleans;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.junit.annotations.TestLogging;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Trace-collection test for the <em>source</em> side of a peer recovery on an encrypted
 * ({@code cryptofs}) index. Produces raw logs for offline analysis; it is deliberately assertion-light.
 *
 * <h2>The question</h2>
 * Peer-recovery phase-1 copies every segment file from the source node to the target. On the source that
 * is a one-pass, zero-reuse bulk read — the same profile as the field data build
 * ({@link FieldDataCacheFlowIntegTests}) and snapshot upload ({@link SnapshotBufferpoolFlowIntegTests}),
 * both of which now bypass the buffer pool. Before proposing the same treatment here, three things have
 * to be observed rather than argued:
 *
 * <ol>
 * <li><b>Which route does the copy actually take?</b> {@code hybrid.openInput} /
 *     {@code pool.openInput ROUTE=...} answer this per file. If the copy never reaches
 *     {@code POOL(L1+L2+readahead)}, there is nothing to bypass and the whole idea is void — which is
 *     the cheapest possible outcome and the reason this test exists before any code change.</li>
 * <li><b>What IOContext does it arrive with?</b> {@code FdcDebug.describe} prints the hint set,
 *     {@code readOnce}, and {@code refEqReadOnce}. Core opens phase-1 files with {@code IOContext.DEFAULT}
 *     (SegmentFileTransferHandler), so the expectation is {@code hints=[] readOnce=false} — i.e. the
 *     plugin cannot currently tell this flow apart from a search read by context alone.</li>
 * <li><b>Is the read sequential in fact, not just in theory?</b> Two independent traces say so:
 *     {@code block.acquire blockOffset=} on the pool path, and {@code niofs.readInternal seq= gap=} on
 *     the NIO path. If the IOContext carries no sequential hint, this is the only evidence available.</li>
 * </ol>
 *
 * <h2>Scenario (fixed, so successive runs are comparable)</h2>
 * node A alone → create 1-shard 0-replica cryptofs index pinned to A → ingest {@value #NUM_DOCS} docs →
 * refresh + flush → start node B → repin the index to B → wait for the relocation to complete → assert
 * the primary really moved. The measurement window is opened immediately before the repin, so counters
 * attribute to the migration rather than to ingest.
 *
 * <h2>How to run (traces land outside the repo)</h2>
 *
 * <pre>
 * ./gradlew internalClusterTest --tests '*PeerRecoverySourceReadTraceIntegTests*' \
 *     -Dfdc.hotstacks=true -Dfdc.poolstate=true -Dfdc.frames=40 \
 *     -Dpr.docs=60000 -Dpr.nocfs=true -Dfdc.run=peer-recovery-trace
 * </pre>
 *
 * <b>Deliberately no {@code -Dfdc.debug=true}</b> — see {@link #setStoreTracing}. The store packages are
 * raised to DEBUG on the live cluster for the migration window only, so ingest is not traced.
 * {@code -Dfdc.hotstacks=true} adds the stack walk at per-block and per-read sites (diagnostic only — never
 * while timing anything); {@code -Dfdc.poolstate=true} inlines pool state at every derivation. Output:
 * {@code <workspace>/debug-internal-cluster-tests/<fdc.run>/<Class>.<method>.log}.
 *
 * <h2>Two limits of this harness, stated up front</h2>
 * <ul>
 * <li>{@code FdcDebug} counters are <b>per-JVM</b> and {@code internalCluster} runs both nodes in one
 *     JVM, so every counter here is source+target combined. Attribute by the {@code path=} field (each
 *     node has its own data dir) or by {@code thread=}, never by a bare counter total.</li>
 * <li>Nothing here is a timing measurement. Tracing with stack walks changes the cost of every read; use it
 *     to establish <em>shape</em>. The per-input {@code readNanos}/{@code acquireNanos} it records are for
 *     comparing flows WITHIN one run, not for absolute cost.</li>
 * </ul>
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@TestLogging(value = "org.opensearch.indices.recovery:TRACE,"
    + "org.opensearch.indices.replication:TRACE,"
    + "org.opensearch.indices.store:TRACE,"
    + "org.opensearch.index.shard:DEBUG,"
    + "org.opensearch.indices.cluster:DEBUG", reason = "full recovery lifecycle: signal -> phase-1 copy -> cleanFiles -> source shard delete. The store "
        + "packages are deliberately NOT raised here - they are raised dynamically for the migration window "
        + "only (see setStoreTracing), because tracing a whole ingest buries the window and pollutes timings")
public class PeerRecoverySourceReadTraceIntegTests extends OpenSearchIntegTestCase {

    private static final String INDEX = "peer-recovery-trace";

    /**
     * Docs to ingest before the migration. 1000 is the default because it is the requested scenario, but at
     * that size the whole shard is a handful of small compound ({@code .cfs}) files that phase-1 copies in
     * one read each — enough to establish the ROUTE and the IOContext, not enough to say anything about the
     * access pattern, which needs many reads per file. Raise it for pattern work: {@code -Dpr.docs=200000}.
     */
    private static final int NUM_DOCS = Integer.getInteger("pr.docs", 1000);

    /**
     * When true, stop Lucene from wrapping segments into compound files, so phase-1 copies real per-field
     * files ({@code .fdt}, {@code .dvd}, {@code .tim}) instead of one {@code .cfs} blob. Off by default to
     * keep the requested scenario intact: {@code -Dpr.nocfs=true}.
     */
    private static final boolean NO_CFS = Booleans.parseBoolean(System.getProperty("pr.nocfs", "false"));

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
            // Small pool on purpose: the interesting question is what the copy EVICTS, and a pool sized
            // well above the index would hide eviction entirely.
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .build();
    }

    @Override
    protected boolean addMockInternalEngine() {
        return false;
    }

    private static Settings cryptoIndexSettingsPinnedTo(String nodeName) {
        Settings.Builder b = Settings
            .builder()
            .put("index.store.type", "cryptofs")
            .put("index.store.crypto.key_provider", "dummy")
            .put("index.store.crypto.kms.key_arn", "dummyArn")
            .put("index.number_of_shards", 1)
            .put("index.number_of_replicas", 0)
            .put("index.routing.allocation.require._name", nodeName);
        if (NO_CFS) {
            // The knob is "index.compound_format" (TieredMergePolicyProvider.INDEX_COMPOUND_FORMAT_SETTING),
            // NOT index.merge.policy.no_cfs_ratio - that name is rejected as an unknown setting.
            b.put("index.compound_format", 0.0);
        }
        return b.build();
    }

    /**
     * A → B primary relocation with the full directory + recovery trace captured.
     *
     * <p>Assertion-light by design: it asserts only that the scenario really happened (the shard moved,
     * the content survived, and the directory was actually exercised during the window) so that a passing
     * run guarantees the log is worth reading. Everything else is left to offline analysis of the raw log —
     * an assertion about the route or the hint set would encode today's behaviour as the expectation,
     * which is exactly the thing under investigation.
     */
    public void testPrimaryRelocationSourceReadTrace() throws Exception {
        final String nodeA = internalCluster().startNode();
        ensureStableCluster(1);
        logger.info("fdc-trace PHASE=setup nodeA={}", nodeA);

        createIndex(INDEX, cryptoIndexSettingsPinnedTo(nodeA));
        ensureGreen(INDEX);
        assertPrimaryOnNode(nodeA);

        logger.info("fdc-trace PHASE=ingest docs={}", NUM_DOCS);
        for (int i = 0; i < NUM_DOCS; i++) {
            index(INDEX, "_doc", String.valueOf(i), "field", "value" + i, "number", i);
        }
        client().admin().indices().prepareRefresh(INDEX).get();
        client().admin().indices().prepareFlush(INDEX).get();

        // Segment inventory before the move: phase-1 copies exactly these files, so the log can be read
        // file-by-file against this list. Deliberately NOT force-merged - the requested scenario is
        // refresh+flush, so whatever segment count that produces is what recovery has to copy.
        logger.info("fdc-trace PHASE=pre-move-segments\n{}", catSegments());
        logger.info("fdc-trace PHASE=pre-move-store\n{}", catShardStores());

        final String nodeB = internalCluster().startNode();
        ensureStableCluster(2);
        logger.info("fdc-trace PHASE=nodeB-joined nodeB={}", nodeB);

        // Open the measurement window as late as possible: everything before this is ingest/flush noise.
        setStoreTracing(true);
        FdcDebug.resetCounters();
        FdcDebug.enableCounting();
        logger.info("fdc-trace PHASE=migration-window-open source={} target={}", nodeA, nodeB);

        client()
            .admin()
            .indices()
            .prepareUpdateSettings(INDEX)
            .setSettings(Settings.builder().put("index.routing.allocation.require._name", nodeB))
            .get();

        // ensureGreen alone is not proof of movement (a started primary still on A satisfies it), so the
        // routing table is checked explicitly.
        ensureGreen(TimeValue.timeValueSeconds(120), INDEX);
        assertPrimaryOnNode(nodeB);
        logger.info("fdc-trace PHASE=migration-complete primary-now-on={}", nodeB);

        // The source-side shard delete is asynchronous (IndicesStore acts on the cluster state AFTER the
        // relocation commits), and it is part of what we came to trace. Wait for it rather than racing it.
        assertBusy(() -> {
            assertThat(
                "source node " + nodeA + " should have released the shard directory",
                internalCluster().getInstance(org.opensearch.indices.IndicesService.class, nodeA).hasIndex(resolveIndex(INDEX)),
                is(false)
            );
        }, 60, java.util.concurrent.TimeUnit.SECONDS);
        logger.info("fdc-trace PHASE=source-shard-released node={}", nodeA);

        final Map<String, Long> counters = FdcDebug.counters();
        setStoreTracing(false);
        logger.info("fdc-trace PHASE=migration-window-closed");
        logger.info("fdc-trace PHASE=counters\n{}", renderCounters(counters));

        // Guard against a vacuously readable log: if the directory was never traced, the whole run is
        // worthless and that must fail loudly rather than produce an empty grep later.
        final long opens = FdcDebug.counterOf("hybrid.openInput") + FdcDebug.counterOf("pool.openInput");
        assertThat("the migration window must contain directory opens; counters were " + counters, opens, greaterThan(0L));

        // Content survived the move (a trace of a broken recovery would be misleading to analyse).
        for (int i = 0; i < NUM_DOCS; i++) {
            assertThat(
                "doc " + i + " wrong after relocation",
                client().prepareGet(INDEX, String.valueOf(i)).get().getSourceAsMap().get("field"),
                equalTo("value" + i)
            );
        }
        assertThat(
            client().prepareSearch(INDEX).setSize(0).setTrackTotalHits(true).get().getHits().getTotalHits().value(),
            equalTo((long) NUM_DOCS)
        );
        logger.info("fdc-trace PHASE=done");
    }

    /**
     * Raises (or resets) the store packages to DEBUG on the live cluster, so {@code fdc-debug} tracing covers
     * the migration window and nothing else.
     *
     * <p>Why dynamic rather than {@code @TestLogging} or {@code -Dfdc.debug=true}: both are process-wide for
     * the whole test, so a 60k-doc ingest gets fully traced. Measured: that produced a 365 MB trace whose
     * on-disk content never even reached the migration window, because the Gradle worker then hung for 24
     * minutes in output forwarding (MessageHub.stop -> awaitTermination) shipping it. It also puts tracing
     * cost inside every timed region, which invalidates the per-input nanos this test records.
     *
     * <p>{@code FdcDebug.on} keys off {@code logger.isDebugEnabled()}, so flipping the level here enables the
     * full trace - routes, call-site chains, per-block acquires, per-read access pattern, timing accumulators
     * - for exactly the window. The copy opens its inputs INSIDE the window, so the per-input latches see the
     * raised level.
     *
     * <p>Do NOT pass {@code -Dfdc.debug=true} with this test: it forces tracing on globally at INFO and
     * defeats the scoping. {@code -Dfdc.hotstacks=true} is additive and still fine.
     */
    private void setStoreTracing(boolean on) {
        Settings.Builder s = Settings.builder();
        if (on) {
            s.put("logger.org.opensearch.index.store", "DEBUG");
        } else {
            s.putNull("logger.org.opensearch.index.store");
        }
        client().admin().cluster().prepareUpdateSettings().setTransientSettings(s).get();
    }

    private void assertPrimaryOnNode(String expectedNodeName) {
        ClusterState state = client().admin().cluster().prepareState().get().getState();
        ShardRouting primary = state.routingTable().index(INDEX).shard(0).primaryShard();
        assertThat("primary [" + INDEX + "][0] should be assigned", primary.assignedToNode(), is(true));
        assertThat(
            "shard [" + INDEX + "][0] should be on " + expectedNodeName,
            state.nodes().get(primary.currentNodeId()).getName(),
            equalTo(expectedNodeName)
        );
    }

    /** Segment inventory, so the copied-file list in the trace can be checked against what existed. */
    private String catSegments() {
        return client().admin().indices().prepareSegments(INDEX).get().getIndices().toString();
    }

    /** Per-shard store sizes, for the byte volume the copy has to move. */
    private String catShardStores() {
        return client().admin().indices().prepareStats(INDEX).setStore(true).get().getPrimaries().getStore().toString();
    }

    private static String renderCounters(Map<String, Long> counters) {
        StringBuilder sb = new StringBuilder(counters.size() * 48);
        counters.forEach((k, v) -> sb.append("  ").append(k).append(" = ").append(v).append('\n'));
        return sb.toString();
    }
}
