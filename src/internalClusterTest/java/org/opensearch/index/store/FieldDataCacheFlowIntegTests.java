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
import org.opensearch.index.store.bufferpoolfs.StaticConfigs;
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
            // Field data eviction is mark-and-sweep, not immediate. _cache/clear?fielddata=true only adds
            // the index to IndicesFieldDataCache#indicesToClear (IndicesFieldDataCache.clear(Index) is a
            // one-line add); the entry stays fully resident, still served and still charged to the breaker,
            // until IndicesService.CacheCleaner ticks and runs the no-arg clear() that actually invalidates.
            // That interval defaults to ONE MINUTE, which makes any clear-then-measure test either
            // minute-long or flaky. 100ms makes the sweep deterministic on a test timescale.
            .put("indices.cache.cleanup_interval", "100ms")
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

        // Phase boundaries around the aggregation. NOTE both the field data build (aggregator construction)
        // and the query phase happen inside this ONE request, so this pair brackets them together; the
        // per-phase split of those two is what testFieldDataBuildPhaseVsQueryPhasePoolState measures.
        beginPhase("agg-request(build+query)");

        // ---- The build. A terms agg on an ANALYZED text field has no doc values to fall back on, so it
        // must uninvert the postings into an on-heap ordinals structure - which is the field data build.
        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setSize(0)
            // The shard request cache would serve an identical repeated agg from its RESPONSE cache, keyed on the
            // index reader's cache key - the aggregation then never executes, no field data is built, and the
            // trace counters come back empty. Measured: this made the rebuild assertion fail ~1 run in 3 with
            // completely empty counters. Any A/B that re-runs the same query MUST disable it or it measures
            // the cache, not the code path.
            .setRequestCache(false)
            .addAggregation(AggregationBuilders.terms("by_user").field(TEXT_FIELD).size(10))
            .get();
        assertNoFailures(response);

        endPhase("agg-request(build+query)");

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
        assertNoFailures(client().prepareSearch(INDEX).setSize(1).setRequestCache(false).get());

        FdcDebug.resetCounters();

        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setSize(0)
            // The shard request cache would serve an identical repeated agg from its RESPONSE cache, keyed on the
            // index reader's cache key - the aggregation then never executes, no field data is built, and the
            // trace counters come back empty. Measured: this made the rebuild assertion fail ~1 run in 3 with
            // completely empty counters. Any A/B that re-runs the same query MUST disable it or it measures
            // the cache, not the code path.
            .setRequestCache(false)
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

        // The clear-cache response returning does NOT mean anything has been evicted. Field data eviction
        // is MARK-AND-SWEEP: this call only adds the index to IndicesFieldDataCache#indicesToClear, and the
        // entry stays fully resident - still served, still charged to the breaker - until
        // IndicesService.CacheCleaner ticks and runs the no-arg clear() that invalidates it. Measured:
        // 816 bytes still charged to `user` immediately after the call AND after a second clear (a second
        // clear just re-marks the same set), reaching zero only once a sweep ran. So assertBusy waits for
        // the SWEEP, not for a lagging counter - which is why nodeSettings pins the interval to 100ms
        // rather than leaving it at its one-minute default.
        assertBusy(() -> assertThat("clearing the field data cache must release it", indexFieldDataBytes(), equalTo(0L)));

        FdcDebug.resetCounters();
        runTermsAgg();

        // Diagnostics BEFORE assertions, deliberately. The first cut of this test logged the counters after
        // the residency assertion, so every failure reported "expected > 0, was 0" with nothing to explain
        // it - the one situation the instrumentation exists for, and the one place it was unavailable.
        Map<String, Long> counts = FdcDebug.counters();
        logger
            .info(
                "fdc-flow: REBUILD counters={} fieldDataNow={} perField={} afterFirstBuild={}",
                counts,
                indexFieldDataBytes(),
                allPerFieldFieldDataBytes(),
                afterFirstBuild
            );

        // A cold rebuild has to reach the block layer again; if it did not, something served it from a
        // cache we did not intend to be in the picture and the "cold" baseline is not cold.
        long work = FdcDebug.counterOf("input.clone") + FdcDebug.counterOf("input.slice") + FdcDebug.counterOf("loader.load") + FdcDebug
            .counterOf("block.acquire.L1_HIT") + FdcDebug.counterOf("block.acquire.L2_HIT") + FdcDebug
                .counterOf("block.acquire.MISS_LOADS_AND_POPULATES");
        assertThat("cold rebuild must do real read work; counters were " + counts, work, greaterThan(0L));

        assertBusy(() -> assertThat("second agg must rebuild field data", indexFieldDataBytes(), greaterThan(0L)));
        assertThat("rebuild should cost the same bytes as the first build", indexFieldDataBytes(), equalTo(afterFirstBuild));
    }

    /**
     * The harm question, answered directly: does building field data touch the block cache at all?
     *
     * <p>It must not. This is the guard on the thread-marker mechanism: core marks the thread around the
     * uninversion, so the build's reads bypass the pool and land in non-pooled buffers. The test asserts
     * that the marker fires, that the reads take the bypass, and that nothing is published.
     *
     * <p>{@link #testFieldDataBuildOpensNoFilesAndOnlyClones} runs warm - every block is already in L1,
     * so no I/O happens and that test can say nothing about the load path. Here the index is closed and
     * reopened first, which drops the directories and invalidates their caches, so the build must reach
     * disk. Only then are these counts meaningful.
     *
     * <p>Note what could NOT be instrumented to answer this: a log line inside
     * {@code CryptoDirectIOBlockLoader.load} cannot distinguish a populating read from a bypassing one.
     * The loader is called from five sites in {@code CaffeineBlockCache} - four publish, {@code
     * loadTransient} does not - and its signature carries nothing identifying the caller. The decision
     * lives with the caller, so it is counted there.
     */
    public void testColdFieldDataBuildBypassesBlockCache() throws Exception {
        internalCluster().startNode();
        createIndexAndIngest();
        enableFieldDataOnTextField();

        // Cold the block cache: closing the index closes the directories, which invalidates the block
        // cache, the L1 tables, the FD cache and the encryption-metadata cache for those paths.
        assertAcked(client().admin().indices().prepareClose(INDEX).get());
        assertAcked(client().admin().indices().prepareOpen(INDEX).get());
        ensureGreen(INDEX);

        FdcDebug.resetCounters();

        runTermsAgg();

        Map<String, Long> counts = FdcDebug.counters();
        logger.info("fdc-flow: counters across the COLD field data build = {}", counts);

        // Residency is deliberately NOT asserted here, and the reason is a conflict between two tests over
        // one node-level knob. indices.cache.cleanup_interval is pinned to 100ms so
        // testClearFieldDataCacheThenRebuild can observe a mark-and-sweep eviction promptly - but frequent
        // sweeps also mean a freshly built entry can be swept out from under this test between the build and
        // the stats read. Observed ~1 run in 7: identical counters (L1_HIT=5, clone=3, slice=4, so the build
        // definitely ran) with the stat reading 0.
        //
        // Residency is already asserted deterministically by testTermsAggOnTextFieldBuildsFieldDataCache,
        // which does no close/open and so is not racing a sweep. What THIS test uniquely establishes is the
        // block-acquisition path, and the counters below prove that synchronously and exactly. Asserting a
        // sweep-gated statistic here would add no coverage and one flaky failure mode.
        logger.info("fdc-flow: COLD build field data bytes={} (sweep-gated, not asserted here)", indexFieldDataBytes());

        long l1Hits = FdcDebug.counterOf("block.acquire.L1_HIT");
        long l2Hits = FdcDebug.counterOf("block.acquire.L2_HIT");
        long misses = FdcDebug.counterOf("block.acquire.MISS_LOADS_AND_POPULATES");
        long hookWidened = FdcDebug.counterOf("input.skipBufferpool.hookWidened");
        long bypassed = FdcDebug.counterOf("input.acquireBlock.BYPASS");
        long notPopulated = FdcDebug.counterOf("cache.loadTransient.NO_POPULATE");

        logger
            .info(
                "fdc-flow: COLD build tiers L1_HIT={} L2_HIT={} MISS_LOADS={} rawIo={} hookWidened={} bypassed={}",
                l1Hits,
                l2Hits,
                misses,
                FdcDebug.counterOf("loader.load"),
                hookWidened,
                bypassed
            );

        // THE CONTRACT, and it is the inverse of what this test asserted before the thread marker landed.
        // The build's source blocks are deliberately NOT mediated by the pool: IndicesFieldDataCache marks
        // the thread around the uninversion, enableSkipBufferpool reads that marker, and every input derived
        // inside the build reads through DirectIO into a non-pooled buffer instead. A field data build is a
        // high-volume sequential read with near-zero reuse, so pooling its blocks evicts what search still
        // needs in order to store what nobody will ask for again.
        assertThat("the thread marker must fire for a field data build; counters were " + counts, hookWidened, greaterThan(0L));
        assertThat("the build's reads must take the bypass; counters were " + counts, bypassed, greaterThan(0L));
        assertThat("bypassed reads must not populate the pool; counters were " + counts, notPopulated, greaterThan(0L));

        // Pin the count, not just its sign. loadDirect performs the uninversion in three statements -
        // estimator slice of the terms index, term-dictionary clone, postings clone - so a correct build
        // widens exactly three derivations. Asserting the number is what makes a silently DEAD marker a
        // test failure: a mechanism that never fires produces zero here while every other assertion in this
        // class still passes, which is how the previous stack-walk mechanism could break unnoticed.
        assertThat("expected exactly the three loadDirect derivations; counters were " + counts, hookWidened, equalTo(3L));
    }

    /**
     * The OTHER mechanism, and the one easily conflated with the first: a terms aggregation on a
     * {@code keyword} field.
     *
     * <p>{@code fielddata: true} on an analyzed {@code text} field uninverts the POSTINGS
     * ({@code .doc} / {@code .tim}) into on-heap ordinals. A {@code keyword} field has doc values, so the
     * same aggregation instead builds a global ordinal map over {@code .dvd} / {@code .dvm}. Both land in
     * {@code IndicesFieldDataCache} and both show up in field data stats, but they read different files
     * through different code paths - so a routing or admission change aimed at one does not necessarily
     * affect the other.
     *
     * <p>This test records which extensions each path actually touches rather than assuming. It asserts
     * only that the keyword path is pool-mediated and that field data becomes resident; the extension mix
     * is logged, because at small scale Lucene writes a compound file and the physical extension is
     * {@code .cfs} regardless of which logical file is being read - the mix is only legible once segments
     * are large enough to stay non-compound.
     */
    public void testKeywordTermsAggUsesDocValuesPath() throws Exception {
        internalCluster().startNode();
        createIndexAndIngest();

        String keywordField = TEXT_FIELD + ".keyword";

        FdcDebug.resetCounters();

        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setSize(0)
            // The shard request cache would serve an identical repeated agg from its RESPONSE cache, keyed on the
            // index reader's cache key - the aggregation then never executes, no field data is built, and the
            // trace counters come back empty. Measured: this made the rebuild assertion fail ~1 run in 3 with
            // completely empty counters. Any A/B that re-runs the same query MUST disable it or it measures
            // the cache, not the code path.
            .setRequestCache(false)
            .addAggregation(AggregationBuilders.terms("by_keyword").field(keywordField).size(10))
            .get();
        assertNoFailures(response);

        Terms terms = response.getAggregations().get("by_keyword");
        assertThat("keyword agg must produce buckets", terms.getBuckets().size(), greaterThan(0));

        Map<String, Long> counts = FdcDebug.counters();
        logger.info("fdc-flow: counters across the KEYWORD (doc values) agg = {}", counts);
        logger.info("fdc-flow: KEYWORD field data perField = {}", allPerFieldFieldDataBytes());

        long tiers = FdcDebug.counterOf("block.acquire.L1_HIT") + FdcDebug.counterOf("block.acquire.L2_HIT") + FdcDebug
            .counterOf("block.acquire.MISS_LOADS_AND_POPULATES");
        assertThat("the keyword agg must also acquire blocks through the pool; counters were " + counts, tiers, greaterThan(0L));

        // No openInput here either: like the text path, the global-ordinal build clones inputs that
        // segment-core construction already opened.
        long opens = FdcDebug.counterOf("hybrid.openInput") + FdcDebug.counterOf("pool.openInput");
        assertThat("keyword agg must not open any file; counters were " + counts, opens, equalTo(0L));
    }

    /**
     * Records buffer-pool state at a phase boundary, alongside the {@link FdcDebug} counter deltas for that
     * phase.
     *
     * <p>Phase boundaries are the only useful sampling points here. The plugin's own telemetry thread emits
     * the same pool records on a 10s cadence, which cannot attribute anything in this test: the field data
     * build and the query phase that follows it are ~7ms apart and land inside one tick. Sampling either
     * side of each phase is what makes "this phase did that to the pool" a measurement rather than a guess.
     *
     * <p>Counters are reset on entry, so each phase's numbers are its own rather than cumulative.
     */
    private void beginPhase(String phase) {
        FdcDebug.resetCounters();
        logger.info("fdc-phase BEGIN  {}  pool={}", phase, CryptoDirectoryFactory.poolStateSnapshot());
    }

    /** Closes a phase opened by {@link #beginPhase}, emitting its counter deltas and the resulting pool state. */
    private Map<String, Long> endPhase(String phase) {
        Map<String, Long> counters = FdcDebug.counters();
        logger
            .info(
                "fdc-phase END    {}  counters={}  fieldDataBytes={}  pool={}",
                phase,
                counters,
                indexFieldDataBytes(),
                CryptoDirectoryFactory.poolStateSnapshot()
            );
        return counters;
    }

    /**
     * Separates the FIELD DATA BUILD from the QUERY PHASE and records buffer-pool state across each.
     *
     * <p>The two cannot be bracketed independently inside one request - the build runs during aggregator
     * construction and the query phase runs immediately after, ~7ms later, in the same call. So the split is
     * obtained by DIFFERENCE: the first aggregation pays build + query, the second pays query only, because
     * the field data entry is now cached (it is keyed on the segment core, so it survives). Whatever the
     * first request did that the second did not is the build.
     *
     * <p>{@code setRequestCache(false)} on both is essential and not incidental: with the response cache on,
     * the second request returns a cached RESPONSE, executes no aggregation at all, and the delta would
     * measure the response cache rather than the build. That failure mode is silent - it shows up as empty
     * counters, which reads like "the build did nothing".
     *
     * <p>Asserts only the invariants that hold at any scale; the pool numbers are logged for reading rather
     * than asserted, because they depend on pool size versus index size, which is a property of the
     * deployment and not of this code path.
     */
    public void testFieldDataBuildPhaseVsQueryPhasePoolState() throws Exception {
        internalCluster().startNode();
        createIndexAndIngest();
        enableFieldDataOnTextField();

        // Warm segment readers WITHOUT touching field data, so segment-core opens are attributed here and
        // not to the build under measurement.
        beginPhase("warmup-plain-search");
        assertNoFailures(client().prepareSearch(INDEX).setSize(1).setRequestCache(false).get());
        endPhase("warmup-plain-search");

        // ---- PHASE 1: field data build + query ----
        beginPhase("phase1-build+query");
        runTermsAgg();
        Map<String, Long> phase1 = endPhase("phase1-build+query");

        assertBusy(() -> assertThat("field data must be resident after phase 1", indexFieldDataBytes(), greaterThan(0L)));

        // ---- PHASE 2: query only; the field data entry is now cached ----
        beginPhase("phase2-query-only");
        runTermsAgg();
        Map<String, Long> phase2 = endPhase("phase2-query-only");

        long derived1 = phase1.getOrDefault("input.clone", 0L) + phase1.getOrDefault("input.slice", 0L);
        long derived2 = phase2.getOrDefault("input.clone", 0L) + phase2.getOrDefault("input.slice", 0L);
        logger.info("fdc-phase DELTA  build-attributable derived inputs = {} - {} = {}", derived1, derived2, derived1 - derived2);

        // The build must cost strictly more derived inputs than a query that skips it. This is the one
        // scale-independent statement: phase 1 does everything phase 2 does, plus the uninversion.
        assertThat(
            "phase 1 (build+query) must derive more inputs than phase 2 (query only); phase1=" + phase1 + " phase2=" + phase2,
            derived1,
            greaterThan(derived2)
        );

        // Neither phase may open a file - both reach the directory only through derived inputs.
        assertThat(
            "no phase may call openInput; phase1=" + phase1,
            phase1.getOrDefault("hybrid.openInput", 0L) + phase1.getOrDefault("pool.openInput", 0L),
            equalTo(0L)
        );
        assertThat(
            "no phase may call openInput; phase2=" + phase2,
            phase2.getOrDefault("hybrid.openInput", 0L) + phase2.getOrDefault("pool.openInput", 0L),
            equalTo(0L)
        );
    }

    /**
     * Runs the aggregation with {@code profile=true} and reports the plugin's crypto read-path metrics
     * alongside the {@link FdcDebug} counters, so the two instruments can be cross-checked.
     *
     * <p>Run it twice to A/B the bypass:
     * <pre>
     * ./gradlew internalClusterTest --tests '*testProfiledAggReportsCryptoReadPathMetrics*' -Dfdc.debug=true -Dfdc.run=prof-cached
     * ./gradlew internalClusterTest --tests '*testProfiledAggReportsCryptoReadPathMetrics*' -Dfdc.debug=true -Dfdc.bypass=true -Dfdc.run=prof-bypass
     * </pre>
     *
     * <p>What differs between the two, and why:
     * <ul>
     * <li>{@code crypto_l1_hits} / {@code crypto_l1_lookup_time} - present when cached, ZERO under bypass.
     *     Not a gap in the profiler: {@code acquireBlock} returns before it obtains the profile handle when
     *     {@code skipBufferpool} is set, because a bypassing read performs no L1 or L2 lookup at all. Zero is the
     *     truthful value.</li>
     * <li>{@code crypto_blocks_decrypted} / {@code crypto_bytes_read} - recorded in the block LOADER, which
     *     is on both paths, so these are the metrics that stay comparable across the A/B. Expect them to
     *     RISE under bypass, since every read reaches disk instead of being served from memory.</li>
     * </ul>
     *
     * <p>Asserts only that profiling was actually active and produced crypto metrics; the values themselves
     * are logged rather than asserted, because they depend on pool size versus working set.
     */
    public void testProfiledAggReportsCryptoReadPathMetrics() throws Exception {
        internalCluster().startNode();
        createIndexAndIngest();
        enableFieldDataOnTextField();

        beginPhase("profiled-agg");
        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setSize(0)
            .setRequestCache(false)
            .setProfile(true)
            .addAggregation(AggregationBuilders.terms("by_user").field(TEXT_FIELD).size(10))
            .get();
        assertNoFailures(response);
        Map<String, Long> counters = endPhase("profiled-agg");

        assertThat("profiling must be enabled for this test to mean anything", response.getProfileResults().isEmpty(), is(false));

        // Sum the crypto_* breakdown entries across every shard and query node. Core reports one breakdown
        // per (query-node, leaf), so a single logical read shows up under whichever node was scoring.
        Map<String, Long> crypto = new java.util.TreeMap<>();
        response.getProfileResults().values().forEach(shard -> shard.getQueryProfileResults().forEach(queryResult -> {
            collectCryptoMetrics(queryResult.getQueryResults(), crypto);
        }));

        // RAW response, so the profile tree can be read exactly as the API returns it rather than through
        // this test's filtering. Emitted in chunks: a single log record this large is truncated by some
        // appenders, which would silently hide the tail.
        String raw = response.toString();
        logger.info("fdc-profile RAW-AGG-RESPONSE length={}", raw.length());
        for (int i = 0; i < raw.length(); i += 4000) {
            logger.info("fdc-profile RAW-AGG[{}] {}", i / 4000, raw.substring(i, Math.min(raw.length(), i + 4000)));
        }

        logger.info("fdc-profile crypto metrics = {}", crypto);
        logger.info("fdc-profile fdc counters   = {}", counters);
        logger.info("fdc-profile bypassEnabled={} fieldDataBytes={}", StaticConfigs.blockCacheBypassEnabled(), indexFieldDataBytes());

        // CONTROL: a query that actually SCORES documents. If this populates crypto metrics while the
        // aggregation above does not, the profiler is not broken - it simply cannot see reads that happen
        // outside leaf scoring, which is where the core ProfileBreakdownHolder exposes a breakdown.
        SearchResponse scoring = client()
            .prepareSearch(INDEX)
            .setSize(DOC_COUNT)
            .setRequestCache(false)
            .setProfile(true)
            .setQuery(org.opensearch.index.query.QueryBuilders.matchAllQuery())
            .get();
        assertNoFailures(scoring);

        Map<String, Long> cryptoScoring = new java.util.TreeMap<>();
        scoring
            .getProfileResults()
            .values()
            .forEach(shard -> shard.getQueryProfileResults().forEach(q -> collectCryptoMetrics(q.getQueryResults(), cryptoScoring)));
        logger.info("fdc-profile CONTROL doc-scoring query crypto metrics = {}", cryptoScoring);

        long aggTotal = crypto.values().stream().mapToLong(Long::longValue).sum();
        long scoringTotal = cryptoScoring.values().stream().mapToLong(Long::longValue).sum();
        logger.info("fdc-profile TOTALS agg={} docScoring={}", aggTotal, scoringTotal);
    }

    /** Walks the profile tree and sums every {@code crypto_*} breakdown entry. */
    private void collectCryptoMetrics(java.util.List<org.opensearch.search.profile.ProfileResult> results, Map<String, Long> into) {
        for (org.opensearch.search.profile.ProfileResult result : results) {
            result.getTimeBreakdown().forEach((k, v) -> {
                if (k.startsWith("crypto_")) {
                    into.merge(k, v, Long::sum);
                }
            });
            collectCryptoMetrics(result.getProfiledChildren(), into);
        }
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
            // The shard request cache would serve an identical repeated agg from its RESPONSE cache, keyed on the
            // index reader's cache key - the aggregation then never executes, no field data is built, and the
            // trace counters come back empty. Measured: this made the rebuild assertion fail ~1 run in 3 with
            // completely empty counters. Any A/B that re-runs the same query MUST disable it or it measures
            // the cache, not the code path.
            .setRequestCache(false)
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
