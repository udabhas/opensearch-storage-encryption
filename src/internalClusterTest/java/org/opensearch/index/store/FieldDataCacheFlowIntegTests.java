/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.opensearch.test.hamcrest.OpenSearchAssertions.assertAcked;
import static org.opensearch.test.hamcrest.OpenSearchAssertions.assertHitCount;
import static org.opensearch.test.hamcrest.OpenSearchAssertions.assertNoFailures;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.opensearch.action.admin.cluster.node.stats.NodesStatsResponse;
import org.opensearch.action.admin.indices.stats.CommonStatsFlags;
import org.opensearch.action.admin.indices.stats.IndicesStatsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.plugins.Plugin;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.bucket.terms.Terms;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.junit.annotations.TestLogging;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Traces how field data is built on an encrypted ({@code cryptofs}) index, and pins the read path it
 * actually uses.
 *
 * <h2>The question</h2>
 * "Field data uses the buffer pool" can mean two different things, with different fixes:
 * <ol>
 * <li>field data itself is stored in the off-heap block cache, or</li>
 * <li>field data lives on heap, and only the <em>reads that build it</em> flow through
 *     {@link org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory} and populate the block
 *     cache as a side effect.</li>
 * </ol>
 * These tests establish that it is (2), and - more usefully - that the build reaches disk
 * <strong>without opening a single file</strong>: it clones inputs that segment-core construction
 * opened earlier, so any routing decision taken at {@code openInput} time cannot see it.
 *
 * <h2>Why counters and not log grepping</h2>
 * The load-bearing facts here are negative ("zero opens during the build"), and a missing log line is
 * indistinguishable from a logger that was never enabled. {@link FdcDebug} counters make the negative
 * checkable: a zero delta across an operation whose <em>other</em> counters moved is evidence, whereas
 * an empty grep is not. {@code @TestLogging} raises the store packages to DEBUG so the counters are
 * live regardless of whether {@code -Dfdc.debug=true} was passed on the command line.
 *
 * <p>Run with per-test trace files:
 * <pre>
 * ./gradlew internalClusterTest --tests '*FieldDataCacheFlowIntegTests*' -Dfdc.debug=true -Dfdc.run=fielddata
 * </pre>
 * Add {@code -Dfdc.hotstacks=true} to get caller chains for the clone and block-load sites, which is
 * what shows <em>which</em> Lucene consumer is driving the build.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
@TestLogging(value = "org.opensearch.index.store:DEBUG", reason = "fdc-debug read-path tracing + FdcDebug counters")
public class FieldDataCacheFlowIntegTests extends OpenSearchIntegTestCase {

    private static final String INDEX = "fdc-flow";
    private static final String TEXT_FIELD = "user";
    private static final int DOC_COUNT = 200;

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

    /**
     * Full flow on one index: ingest, prove field data is empty, enable {@code fielddata} on an analyzed
     * text field, run a terms aggregation, then prove field data is resident and cross-check the number
     * against a second instrument.
     */
    public void testTermsAggOnTextFieldBuildsFieldDataCache() throws Exception {
        internalCluster().startNode();
        createIndexAndIngest();

        // ---- BEFORE: nothing resident. Establishes that whatever we measure later was built by the agg.
        assertThat("field data must start empty", indexFieldDataBytes(), equalTo(0L));

        enableFieldDataOnTextField();

        // ---- The build. A terms agg on an ANALYZED text field has no doc values to fall back on, so it
        // must uninvert the postings into an on-heap ordinals structure - which is the field data build.
        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setSize(0)
            .addAggregation(AggregationBuilders.terms("by_user").field(TEXT_FIELD).size(10))
            .get();
        assertNoFailures(response);

        Terms terms = response.getAggregations().get("by_user");
        assertThat("agg must produce buckets or the build did not happen", terms.getBuckets().size(), greaterThan(0));

        // ---- AFTER: resident, and confirmed by two independent instruments that must agree.
        long viaIndicesStats = indexFieldDataBytes();
        assertThat("field data should be resident after the agg", viaIndicesStats, greaterThan(0L));

        long viaNodesStats = nodeFieldDataBytes();
        assertThat("indices stats and nodes stats must agree on field data size", viaNodesStats, equalTo(viaIndicesStats));

        // ---- Attribution: the bytes must be charged to the field we enabled, not to something else.
        long perField = perFieldFieldDataBytes(TEXT_FIELD);
        assertThat("field data must be attributed to " + TEXT_FIELD, perField, greaterThan(0L));
        assertThat("per-field bytes cannot exceed the index total", perField <= viaIndicesStats, is(true));

        logger
            .info(
                "fdc-flow: field data resident bytes={} (per-field {}={}), buckets={}",
                viaIndicesStats,
                TEXT_FIELD,
                perField,
                terms.getBuckets().size()
            );
    }

    /**
     * The structural finding, asserted rather than eyeballed: the field data build performs
     * <strong>zero</strong> {@code openInput} calls, and reaches the block layer purely through
     * {@code clone()} / {@code slice()} of inputs opened during segment-core construction.
     *
     * <p>Consequence for routing design: a skip-the-cache decision taken at {@code openInput} time is
     * structurally blind to this flow. The decision has to be reachable at clone time, because that is
     * the only seam the build actually crosses.
     *
     * <p>The assertion is deliberately one-sided. Zero opens is the claim; a non-zero clone or block
     * count in the same window is what makes the zero meaningful rather than vacuous.
     */
    public void testFieldDataBuildOpensNoFilesAndOnlyClones() throws Exception {
        internalCluster().startNode();
        createIndexAndIngest();
        enableFieldDataOnTextField();

        // Warm the segment readers WITHOUT touching field data, so the opens that segment-core
        // construction performs are attributed to this query and not to the build we are measuring.
        assertNoFailures(client().prepareSearch(INDEX).setSize(1).get());

        FdcDebug.resetCounters();

        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setSize(0)
            .addAggregation(AggregationBuilders.terms("by_user").field(TEXT_FIELD).size(10))
            .get();
        assertNoFailures(response);

        Map<String, Long> counts = FdcDebug.counters();
        logger.info("fdc-flow: counters across the field data build = {}", counts);

        long opens = FdcDebug.counterOf("hybrid.openInput") + FdcDebug.counterOf("pool.openInput");
        long derived = FdcDebug.counterOf("input.clone") + FdcDebug.counterOf("input.slice");
        long blockLoads = FdcDebug.counterOf("loader.load");

        assertThat("field data must be resident, else there was no build to measure", indexFieldDataBytes(), greaterThan(0L));

        // The zero only means something if the build demonstrably did work in this window.
        assertThat(
            "expected clone/slice or block-load activity during the build; counters were " + counts,
            derived + blockLoads,
            greaterThan(0L)
        );
        assertThat("field data build must not open any file; counters were " + counts, opens, equalTo(0L));
    }

    /**
     * Clearing the field data cache must release the heap, and a second aggregation must rebuild it.
     * This is what makes the build repeatable, which any later A/B of the read path depends on: a
     * measurement you cannot re-run from a known-cold state is not a measurement.
     */
    public void testClearFieldDataCacheThenRebuild() throws Exception {
        internalCluster().startNode();
        createIndexAndIngest();
        enableFieldDataOnTextField();

        runTermsAgg();
        long afterFirstBuild = indexFieldDataBytes();
        assertThat("first build should populate field data", afterFirstBuild, greaterThan(0L));

        client().admin().indices().prepareClearCache(INDEX).setFieldDataCache(true).get();

        // The clear-cache response returning does NOT mean the field data accounting has dropped to zero.
        // Measured here: immediately after the call, and again after a second clear, the field is still
        // charged (observed 816 bytes for `user`); it reaches zero on its own shortly after. A second
        // clear does not help but elapsed time does, so the eviction is applied synchronously while the
        // accounting decrement - the cache's removal listener - runs asynchronously. Hence assertBusy and
        // not a bare assert: a hard assert here fails intermittently, and a fixed sleep would just hide
        // the same race behind a magic number.
        assertBusy(() -> assertThat("clearing the field data cache must release it", indexFieldDataBytes(), equalTo(0L)));

        FdcDebug.resetCounters();
        runTermsAgg();

        long afterRebuild = indexFieldDataBytes();
        assertThat("second agg must rebuild field data", afterRebuild, greaterThan(0L));
        assertThat("rebuild should cost the same bytes as the first build", afterRebuild, equalTo(afterFirstBuild));

        // A cold rebuild has to reach the block layer again; if it did not, something served it from a
        // cache we did not intend to be in the picture and the "cold" baseline is not cold.
        Map<String, Long> counts = FdcDebug.counters();
        logger.info("fdc-flow: counters across the COLD rebuild = {}", counts);
        long work = FdcDebug.counterOf("input.clone") + FdcDebug.counterOf("input.slice") + FdcDebug.counterOf("loader.load");
        assertThat("cold rebuild must do real read work; counters were " + counts, work, greaterThan(0L));
    }

    // ---- helpers ----

    private void createIndexAndIngest() throws Exception {
        assertAcked(client().admin().indices().prepareCreate(INDEX).setSettings(cryptoIndexSettings()).get());
        ensureGreen(INDEX);

        for (int i = 0; i < DOC_COUNT; i++) {
            // A small, bounded term vocabulary so the uninverted ordinals are non-trivial but the terms
            // agg result stays assertable.
            client()
                .prepareIndex(INDEX)
                .setId(Integer.toString(i))
                .setSource(TEXT_FIELD, "user" + (i % 10) + " session" + (i % 4), "value", i)
                .get();
        }
        client().admin().indices().prepareRefresh(INDEX).get();
        assertHitCount(client().prepareSearch(INDEX).setSize(0).get(), DOC_COUNT);
    }

    /**
     * {@code fielddata} is updatable on an existing text field, so this needs no reindex. Note the field
     * is ANALYZED: the agg buckets are tokens, not whole values. That is irrelevant to the flow being
     * traced but it is why the bucket keys look like single tokens rather than field values.
     */
    private void enableFieldDataOnTextField() {
        assertAcked(
            client()
                .admin()
                .indices()
                .preparePutMapping(INDEX)
                .setSource("{\"properties\":{\"" + TEXT_FIELD + "\":{\"type\":\"text\",\"fielddata\":true}}}", MediaTypeRegistry.JSON)
                .get()
        );
    }

    private void runTermsAgg() {
        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setSize(0)
            .addAggregation(AggregationBuilders.terms("by_user").field(TEXT_FIELD).size(10))
            .get();
        assertNoFailures(response);
    }

    private long indexFieldDataBytes() {
        IndicesStatsResponse stats = client().admin().indices().prepareStats(INDEX).clear().setFieldData(true).get();
        return stats.getTotal().getFieldData().getMemorySizeInBytes();
    }

    private long nodeFieldDataBytes() {
        NodesStatsResponse stats = client().admin().cluster().prepareNodesStats("data:true").setIndices(true).get();
        long total = 0;
        for (int i = 0; i < stats.getNodes().size(); i++) {
            total += stats.getNodes().get(i).getIndices().getFieldData().getMemorySizeInBytes();
        }
        return total;
    }

    /** Full per-field breakdown, so a residual byte count can be attributed instead of guessed at. */
    private Map<String, Long> allPerFieldFieldDataBytes() {
        NodesStatsResponse stats = client()
            .admin()
            .cluster()
            .prepareNodesStats("data:true")
            .setIndices(new CommonStatsFlags().set(CommonStatsFlags.Flag.FieldData, true).fieldDataFields("*"))
            .get();
        Map<String, Long> out = new java.util.TreeMap<>();
        for (int i = 0; i < stats.getNodes().size(); i++) {
            var fd = stats.getNodes().get(i).getIndices().getFieldData();
            if (fd != null && fd.getFields() != null) {
                for (Map.Entry<String, Long> e : fd.getFields()) {
                    out.merge(e.getKey(), e.getValue(), Long::sum);
                }
            }
        }
        return out;
    }

    private long perFieldFieldDataBytes(String field) {
        NodesStatsResponse stats = client()
            .admin()
            .cluster()
            .prepareNodesStats("data:true")
            .setIndices(new CommonStatsFlags().set(CommonStatsFlags.Flag.FieldData, true).fieldDataFields("*"))
            .get();
        long total = 0;
        for (int i = 0; i < stats.getNodes().size(); i++) {
            var fd = stats.getNodes().get(i).getIndices().getFieldData();
            if (fd != null && fd.getFields() != null) {
                total += fd.getFields().get(field);
            }
        }
        return total;
    }
}
