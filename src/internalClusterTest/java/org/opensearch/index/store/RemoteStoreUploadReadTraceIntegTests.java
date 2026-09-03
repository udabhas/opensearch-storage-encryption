/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.lucene.tests.util.LuceneTestCase.SuppressFileSystems;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.Booleans;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.plugins.Plugin;
import org.opensearch.remotestore.RemoteStoreBaseIntegTestCase;
import org.opensearch.remotestore.multipart.mocks.MockFsRepositoryPlugin;
import org.opensearch.repositories.fs.ReloadableFsRepository;
import org.opensearch.search.SearchHit;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.junit.annotations.TestLogging;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Trace-collection test for the remote-store <em>segment upload</em> read path on an encrypted
 * ({@code cryptofs}) index, plus the search reads that follow. Produces raw logs for offline analysis;
 * it is deliberately assertion-light about the behaviour under study.
 *
 * <h2>The question</h2>
 * Remote-store segment upload streams every new segment file to the remote store exactly once and never
 * re-reads it — the same one-pass, zero-reuse profile that already justified a buffer-pool bypass for the
 * field data build ({@link FieldDataCacheFlowIntegTests}), snapshot upload
 * ({@link SnapshotBufferpoolFlowIntegTests}) and the peer-recovery phase-1 copy
 * ({@link PeerRecoverySourceReadTraceIntegTests}). Before proposing the same treatment, four things have to
 * be <em>observed</em> rather than argued:
 *
 * <ol>
 * <li><b>Does the upload reach the buffer pool at all?</b> {@code pool.openInput ROUTE=...} answers this per
 *     file. Note that {@code hybrid.openInput} alone <em>cannot</em>: it fires BEFORE routing, and reading it
 *     as if it showed the outcome is exactly the mistake that produced a wrong root cause once already
 *     (journal &sect;46 &rarr; R49.5). If the upload never reaches {@code POOL(L1+L2+readahead)} there is
 *     nothing to bypass and the whole idea is void — the cheapest possible outcome, which is why this test
 *     exists before any code change.</li>
 * <li><b>Is it a fresh {@code openInput}, or a clone/slice?</b> Both, per code reading — one master open per
 *     file plus one derived input per upload part — and that combination is new: snapshot never derives, and
 *     the field data build never opens. {@code input.create isSlice=}, {@code input.clone} and
 *     {@code input.slice} settle it, and the ratio decides whether an open-time decision is sufficient (it is
 *     only if {@code buildSlice} inheritance carries it to every part).</li>
 * <li><b>What IOContext does it arrive with?</b> {@code FdcDebug.describe} prints the hint set,
 *     {@code readOnce} and {@code refEqReadOnce}. Core opens the upload with a bare {@code IOContext.DEFAULT}
 *     ({@code RemoteStoreUploaderService}), so the expectation is {@code hints=[] readOnce=false} — i.e. the
 *     plugin currently cannot tell this flow from a search read by context alone.</li>
 * <li><b>Is the read sequential in fact?</b> Two independent traces say so or not:
 *     {@code block.acquire blockOffset=} on the pool path and {@code niofs.readInternal seq= gap=} on the NIO
 *     path. With no sequential hint in the context, this is the only evidence available.</li>
 * </ol>
 *
 * <h2>Scenario</h2>
 * one node &rarr; 1-shard 0-replica {@code cryptofs} index with remote store enabled &rarr; ingest
 * {@value #NUM_DOCS} docs in {@value #BATCHES} batches, each followed by refresh + flush (so the upload runs
 * several times over growing segment sets) &rarr; prove the bytes really reached the remote store, from the
 * repository directory on disk as well as from {@code _remotestore/stats} &rarr; run a search battery and
 * assert every document is returned with its exact value.
 *
 * <p>Two measurement windows are opened and closed separately, so counters attribute to a flow rather than to
 * "the test": <b>UPLOAD</b> (ingest + refresh + flush) and <b>SEARCH</b>. Everything outside them is untraced.
 *
 * <h2>Repository type is PINNED, and that matters more than it looks</h2>
 * {@link RemoteStoreBaseIntegTestCase#asyncUploadMockFsRepo} defaults to {@code randomBoolean()}, and the two
 * values exercise <b>structurally different upload code</b>:
 * <ul>
 * <li>{@code fs} ({@code ReloadableFsRepository}) is not an {@code AsyncMultiStreamBlobContainer}, so
 *     {@code RemoteDirectory.copyFrom} returns false and the upload falls back to the synchronous
 *     {@code Directory.copyFrom} — one {@code openInput}, <b>zero part derivations</b>.</li>
 * <li>{@code fs_multipart_repository} ({@code MockFsAsyncBlobContainer implements AsyncMultiStreamBlobContainer})
 *     takes the real multipart path: 10 parts, each on its own thread, each calling
 *     {@code provideStream(partIdx)} &rarr; {@code indexInput.clone()} / {@code .slice()}. That is the shape
 *     production takes on S3.</li>
 * </ul>
 * So an unpinned run traces one of two different flows, 50/50, and the log would not say which. This test
 * pins it deterministically and records the choice in the log. Default is the multipart path because it is the
 * production shape; {@code -Drs.async=false} traces the fallback for comparison. Both are filesystem-backed,
 * so no S3 credentials are involved either way.
 *
 * <h2>How to run (traces land outside the repo)</h2>
 *
 * <pre>
 * ./gradlew internalClusterTest --tests '*RemoteStoreUploadReadTraceIntegTests*' \
 *     -Dfdc.hotstacks=true -Dfdc.frames=40 -Dfdc.poolstate=true \
 *     -Drs.docs=100 -Dfdc.run=rs-upload-trace
 * </pre>
 *
 * <b>Deliberately no {@code -Dfdc.debug=true}</b> — see {@link #setStoreTracing}. The store packages are
 * raised to DEBUG on the live cluster for each window only, so untraced setup does not bury the windows.
 * Output: {@code <workspace>/debug-internal-cluster-tests/<fdc.run>/<Class>.<method>.log}.
 *
 * <h2>Limits of this harness, stated up front</h2>
 * <ul>
 * <li>{@code FdcDebug} counters are <b>per-JVM</b>. Here there is one data node, so totals are unambiguous —
 *     but they still mix the upload flow with refresh/NRT reader opens happening in the same window.
 *     Attribute by {@code callsite=} chain, never by a bare total.</li>
 * <li>The mock multipart container reads its parts on plain {@code new Thread(...)} workers, not on the S3
 *     plugin's {@code [stream_reader]} pools. The <em>structure</em> (one master, N derived inputs, read
 *     concurrently off the opening thread) is faithful; the thread <em>names</em> are not.</li>
 * <li>Nothing here is a timing measurement. Tracing with stack walks changes the cost of every read. The
 *     per-input {@code readNanos}/{@code acquireNanos} are for comparing flows WITHIN one run.</li>
 * </ul>
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@SuppressFileSystems("LeakFS")
@TestLogging(value = "org.opensearch.index.shard:DEBUG,"
    + "org.opensearch.index.remote:DEBUG,"
    + "org.opensearch.indices.recovery:DEBUG,"
    + "org.opensearch.indices.replication:DEBUG", reason = "remote-store upload lifecycle: refresh -> syncSegments -> uploadSegments -> metadata upload. The "
        + "org.opensearch.index.store packages are deliberately NOT raised here - they are raised dynamically "
        + "per measurement window (see setStoreTracing), so untraced setup cannot bury the windows")
public class RemoteStoreUploadReadTraceIntegTests extends RemoteStoreBaseIntegTestCase {

    private static final String INDEX = "rs-upload-trace";

    /** Docs to ingest. 100 is the requested scenario; raise for access-pattern work: {@code -Drs.docs=200000}. */
    private static final int NUM_DOCS = Integer.getInteger("rs.docs", 100);

    /**
     * Ingest is split into batches, each followed by refresh + flush, so the upload runs several times over a
     * growing segment set rather than once. That is what makes the trace show repeated upload rounds (and any
     * per-round re-read of already-uploaded files) instead of a single flush.
     */
    private static final int BATCHES = Integer.getInteger("rs.batches", 4);

    /**
     * Pins the repository type. {@code true} (default) = {@code fs_multipart_repository}, the
     * {@code AsyncMultiStreamBlobContainer} path with per-part derived inputs, which is the production shape.
     * {@code false} = plain {@code fs}, which takes the synchronous single-read fallback. See the class javadoc.
     */
    private static final boolean ASYNC_MULTIPART = Booleans.parseBoolean(System.getProperty("rs.async", "true"));

    /**
     * When true, stop Lucene wrapping segments into compound files, so the upload moves real per-field files
     * ({@code .fdt}, {@code .dvd}, {@code .tim}) instead of one {@code .cfs} blob. Off by default to keep the
     * requested scenario intact; at 100 docs everything is compound and the per-extension view collapses to
     * {@code .cfs}, so set {@code -Drs.nocfs=true} when the extension mix is what you are after.
     */
    private static final boolean NO_CFS = Booleans.parseBoolean(System.getProperty("rs.nocfs", "false"));

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        // Deliberately not delegating the repo-plugin choice to the base class: it keys that off
        // asyncUploadMockFsRepo, which is randomBoolean(). Pinned here so the traced flow is deterministic.
        Stream<Class<? extends Plugin>> crypto = Stream
            .of(CryptoDirectoryPlugin.class, MockCryptoKeyProviderPlugin.class, MockCryptoPlugin.class);
        Stream<Class<? extends Plugin>> repo = ASYNC_MULTIPART ? Stream.of(MockFsRepositoryPlugin.class) : Stream.empty();
        return Stream.concat(Stream.concat(super.nodePlugins().stream(), crypto), repo).distinct().collect(Collectors.toList());
    }

    /**
     * Pinned repository wiring - overrides the base class's randomised choice.
     *
     * <p><b>Only the SEGMENT repository is switched to the multipart mock.</b> The translog repository stays on
     * {@code reloadable-fs} (the base class default) on purpose: putting the translog on the async multipart
     * container trips a core assertion during {@code postActivatePrimaryMode}, before this test reaches its
     * first document —
     * {@code BlobStoreTransferService:203  assert (fileSnapshot.getChecksum() != null || name.contains("-1."))}
     * — reached via {@code RemoteFsTranslog.sync -> DecryptingTranslogTransferManager.transferSnapshot ->
     * uploadBlobs}. That is the same known-flaky remote-translog path that
     * {@code CryptoRemoteStoreIntegTests#testSegRepReplicaPromotionRemoteStoreReadsCorrectContent} is
     * {@code @AwaitsFix}'d on, it is a translog-flow defect rather than anything to do with segment upload, and
     * this track is about the SEGMENT upload read path. Keeping the translog on the synchronous container
     * sidesteps it without weakening what is being measured; both repositories remain filesystem-backed.
     */
    @Override
    protected Settings remoteStoreRepoSettings() {
        return remoteStoreClusterSettings(
            REPOSITORY_NAME,
            segmentRepoPath,
            ASYNC_MULTIPART ? MockFsRepositoryPlugin.TYPE : ReloadableFsRepository.TYPE,
            REPOSITORY_2_NAME,
            translogRepoPath,
            ReloadableFsRepository.TYPE
        );
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings
            .builder()
            .put(super.nodeSettings(nodeOrdinal))
            .put("plugins.crypto.enabled", true)
            // Small pool on purpose: the question is what the upload DISPLACES, and a pool sized well above the
            // index would hide eviction entirely.
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .build();
    }

    @Override
    protected boolean addMockInternalEngine() {
        return false;
    }

    private static Settings cryptoRemoteStoreIndexSettings() {
        Settings.Builder b = Settings
            .builder()
            .put("index.store.type", "cryptofs")
            .put("index.store.crypto.key_provider", "dummy")
            .put("index.store.crypto.kms.key_arn", "dummyArn")
            .put("index.number_of_shards", 1)
            .put("index.number_of_replicas", 0);
        if (NO_CFS) {
            // The knob is "index.compound_format" (TieredMergePolicyProvider.INDEX_COMPOUND_FORMAT_SETTING);
            // "index.merge.policy.no_cfs_ratio" is rejected as an unknown setting.
            b.put("index.compound_format", 0.0);
        }
        return b.build();
    }

    /**
     * Ingest &rarr; upload &rarr; search, with the full directory trace captured for each window.
     *
     * <p>Assertion-light about the behaviour under study on purpose: it asserts only that the scenario really
     * happened (docs landed, bytes reached the remote store, searches are exact, and the directory was
     * actually exercised in each window) so that a passing run guarantees the log is worth reading. Asserting
     * the route or the hint set would encode today's behaviour as the expectation, which is the thing under
     * investigation.
     */
    public void testRemoteStoreUploadAndSearchReadTrace() throws Exception {
        final String node = internalCluster().startNode();
        ensureStableCluster(1);

        logger
            .info(
                "fdc-trace PHASE=setup node={} docs={} batches={} asyncMultipart={} repoType={} nocfs={}",
                node,
                NUM_DOCS,
                BATCHES,
                ASYNC_MULTIPART,
                ASYNC_MULTIPART ? MockFsRepositoryPlugin.TYPE : "fs",
                NO_CFS
            );
        logger.info("fdc-trace PHASE=setup segmentRepoPath={} translogRepoPath={}", segmentRepoPath, translogRepoPath);

        createIndex(INDEX, cryptoRemoteStoreIndexSettings());
        ensureGreen(INDEX);
        logger.info("fdc-trace PHASE=index-created settings\n{}", indexSettingsDump());

        // ---------------------------------------------------------------- UPLOAD WINDOW
        logger.info("fdc-trace PHASE=upload-window-open sample\n{}", sample("before-upload"));
        setStoreTracing(true);
        FdcDebug.resetCounters();
        FdcDebug.enableCounting();

        final int perBatch = Math.max(1, NUM_DOCS / BATCHES);
        int written = 0;
        for (int batch = 0; batch < BATCHES && written < NUM_DOCS; batch++) {
            int upTo = (batch == BATCHES - 1) ? NUM_DOCS : Math.min(NUM_DOCS, written + perBatch);
            logger.info("fdc-trace PHASE=ingest-batch batch={} docs=[{},{})", batch, written, upTo);
            for (int i = written; i < upTo; i++) {
                index(INDEX, "_doc", String.valueOf(i), "field", "value" + i, "number", i);
            }
            written = upTo;
            // refresh THEN flush: refresh is what drives RemoteStoreRefreshListener -> syncSegments -> upload;
            // flush additionally commits and uploads translog, so both remote flows are exercised per batch.
            client().admin().indices().prepareRefresh(INDEX).get();
            client().admin().indices().prepareFlush(INDEX).get();
            logger.info("fdc-trace PHASE=ingest-batch-flushed batch={} written={}", batch, written);
        }
        assertThat("ingest must have written every requested doc", written, equalTo(NUM_DOCS));

        // The upload is asynchronous with respect to refresh, so wait for it rather than racing it.
        awaitRemoteStoreUploadsSettled();

        final Map<String, Long> uploadCounters = FdcDebug.counters();
        setStoreTracing(false);
        logger.info("fdc-trace PHASE=upload-window-closed");
        logger.info("fdc-trace PHASE=upload-counters\n{}", renderCounters(uploadCounters));
        logger.info("fdc-trace PHASE=upload-window-close sample\n{}", sample("after-upload"));

        // Guard against a vacuously readable log: if the directory was never traced in the window, the run is
        // worthless and that must fail loudly rather than produce an empty grep during analysis.
        final long uploadOpens = counterSum(uploadCounters, "hybrid.openInput", "pool.openInput", "niofs.openInput");
        assertThat("the upload window must contain directory opens; counters were " + uploadCounters, uploadOpens, greaterThan(0L));

        // ---------------------------------------------------------------- REMOTE STORE PROOF
        logger.info("fdc-trace PHASE=segments\n{}", catSegments());
        logger.info("fdc-trace PHASE=store-stats\n{}", catShardStore());
        logger.info("fdc-trace PHASE=remote-store-stats\n{}", remoteStoreStatsDump());
        logger.info("fdc-trace PHASE=remote-repo-tree\n{}", repoTree(segmentRepoPath, "SEGMENT-REPO"));
        logger.info("fdc-trace PHASE=remote-repo-tree\n{}", repoTree(translogRepoPath, "TRANSLOG-REPO"));
        assertRemoteStoreReceivedData();

        // ---------------------------------------------------------------- SEARCH WINDOW
        logger.info("fdc-trace PHASE=search-window-open sample\n{}", sample("before-search"));
        setStoreTracing(true);
        FdcDebug.resetCounters();
        FdcDebug.enableCounting();

        runSearchBattery();

        final Map<String, Long> searchCounters = FdcDebug.counters();
        setStoreTracing(false);
        logger.info("fdc-trace PHASE=search-window-closed");
        logger.info("fdc-trace PHASE=search-counters\n{}", renderCounters(searchCounters));
        logger.info("fdc-trace PHASE=search-window-close sample\n{}", sample("after-search"));

        final long searchReads = counterSum(searchCounters, "block.acquire", "niofs.readInternal", "input.clone", "input.slice");
        assertThat("the search window must contain directory reads; counters were " + searchCounters, searchReads, greaterThan(0L));

        logger.info("fdc-trace PHASE=final-remote-store-stats\n{}", remoteStoreStatsDump());
        logger.info("fdc-trace PHASE=done");
    }

    // ------------------------------------------------------------------ searches

    /**
     * A battery chosen to touch different file types rather than to be exhaustive: stored fields
     * ({@code .fdt}) via {@code _source} fetch, postings ({@code .doc}/{@code .tim}) via term and match
     * queries, points ({@code .kdd}) via the numeric range, and doc values ({@code .dvd}) via sort and both
     * aggregations. Accuracy is asserted on every one of them, because a trace of a broken search would be
     * misleading to analyse.
     */
    private void runSearchBattery() {
        logger.info("fdc-trace PHASE=search op=match-all-with-source");
        assertAllDocsExactlyOnce();

        logger.info("fdc-trace PHASE=search op=term-on-keyword");
        for (int probe : new int[] { 0, NUM_DOCS / 2, NUM_DOCS - 1 }) {
            SearchResponse r = client()
                .prepareSearch(INDEX)
                .setQuery(QueryBuilders.termQuery("field.keyword", "value" + probe))
                .setTrackTotalHits(true)
                .get();
            assertThat("term query on field.keyword=value" + probe, r.getHits().getTotalHits().value(), equalTo(1L));
            assertThat(r.getHits().getHits()[0].getId(), equalTo(String.valueOf(probe)));
        }

        logger.info("fdc-trace PHASE=search op=match-on-text");
        SearchResponse match = client()
            .prepareSearch(INDEX)
            .setQuery(QueryBuilders.matchQuery("field", "value7"))
            .setTrackTotalHits(true)
            .get();
        assertThat("match query must find the analysed term", match.getHits().getTotalHits().value(), greaterThan(0L));

        logger.info("fdc-trace PHASE=search op=numeric-range");
        int from = NUM_DOCS / 4;
        int to = NUM_DOCS / 2;
        SearchResponse range = client()
            .prepareSearch(INDEX)
            .setQuery(QueryBuilders.rangeQuery("number").gte(from).lt(to))
            .setSize(0)
            .setTrackTotalHits(true)
            .get();
        assertThat("range [" + from + "," + to + ") on number", range.getHits().getTotalHits().value(), equalTo((long) (to - from)));

        logger.info("fdc-trace PHASE=search op=sort-on-number-desc");
        SearchResponse sorted = client()
            .prepareSearch(INDEX)
            .setQuery(QueryBuilders.matchAllQuery())
            .addSort("number", org.opensearch.search.sort.SortOrder.DESC)
            .setSize(5)
            .setTrackTotalHits(true)
            .get();
        assertThat(sorted.getHits().getTotalHits().value(), equalTo((long) NUM_DOCS));
        assertThat("top hit of a desc sort on number", sorted.getHits().getHits()[0].getId(), equalTo(String.valueOf(NUM_DOCS - 1)));

        logger.info("fdc-trace PHASE=search op=terms-agg-on-keyword");
        SearchResponse termsAgg = client()
            .prepareSearch(INDEX)
            .setSize(0)
            .setRequestCache(false)
            .addAggregation(AggregationBuilders.terms("byField").field("field.keyword").size(NUM_DOCS))
            .setTrackTotalHits(true)
            .get();
        assertThat(
            "terms agg must produce one bucket per distinct value",
            ((org.opensearch.search.aggregations.bucket.terms.Terms) termsAgg.getAggregations().get("byField")).getBuckets().size(),
            equalTo(NUM_DOCS)
        );

        logger.info("fdc-trace PHASE=search op=stats-agg-on-number");
        SearchResponse statsAgg = client()
            .prepareSearch(INDEX)
            .setSize(0)
            .setRequestCache(false)
            .addAggregation(AggregationBuilders.stats("numberStats").field("number"))
            .get();
        org.opensearch.search.aggregations.metrics.Stats stats = statsAgg.getAggregations().get("numberStats");
        assertThat("stats agg count", stats.getCount(), equalTo((long) NUM_DOCS));
        assertThat("stats agg min", (int) stats.getMin(), equalTo(0));
        assertThat("stats agg max", (int) stats.getMax(), equalTo(NUM_DOCS - 1));

        // Repeat the whole-corpus read once more: the second pass is the one that shows whether the blocks the
        // first pass admitted were re-hit (L1_HIT/L2_HIT) or re-read from disk.
        logger.info("fdc-trace PHASE=search op=match-all-second-pass");
        assertAllDocsExactlyOnce();
    }

    /** Every doc returned exactly once, with its exact decrypted value - not merely the right count. */
    private void assertAllDocsExactlyOnce() {
        SearchResponse response = client()
            .prepareSearch(INDEX)
            .setQuery(QueryBuilders.matchAllQuery())
            .setSize(NUM_DOCS)
            .setTrackTotalHits(true)
            .get();
        assertThat(response.getHits().getTotalHits().value(), equalTo((long) NUM_DOCS));
        boolean[] seen = new boolean[NUM_DOCS];
        for (SearchHit hit : response.getHits().getHits()) {
            int i = Integer.parseInt(hit.getId());
            assertThat("doc " + i + " has wrong content", hit.getSourceAsMap().get("field"), equalTo("value" + i));
            assertThat("doc " + i + " has wrong number", hit.getSourceAsMap().get("number"), equalTo(i));
            assertThat("doc " + i + " returned twice", seen[i], is(false));
            seen[i] = true;
        }
        for (int i = 0; i < NUM_DOCS; i++) {
            assertThat("doc " + i + " missing from the result set", seen[i], is(true));
        }
    }

    // ------------------------------------------------------------------ remote store proof

    /**
     * Waits until the shard reports no outstanding segment upload work. Uses the remote-store stats rather than
     * a sleep, because a sleep would either be flaky or slow and could not distinguish "upload finished" from
     * "upload never started".
     */
    private void awaitRemoteStoreUploadsSettled() throws Exception {
        assertBusy(() -> {
            var stats = client().admin().cluster().prepareRemoteStoreStats(INDEX, "0").get();
            assertThat("remote store stats must report the shard", stats.getRemoteStoreStats().length, greaterThan(0));
            for (var shard : stats.getRemoteStoreStats()) {
                var seg = shard.getSegmentStats();
                assertThat("uploads must have started", seg.totalUploadsStarted, greaterThan(0L));
                assertThat("no upload may have failed", seg.totalUploadsFailed, equalTo(0L));
                assertThat("every started upload must have succeeded", seg.totalUploadsSucceeded, equalTo(seg.totalUploadsStarted));
                assertThat("refresh lag must have drained", seg.bytesLag, equalTo(0L));
            }
        }, 120, TimeUnit.SECONDS);
        logger.info("fdc-trace PHASE=remote-uploads-settled");
    }

    /**
     * Two independent proofs that the data really is in the remote store: the shard's own upload accounting,
     * and actual blobs on disk under the repository path. Either alone is weak — stats could be reported for
     * work that failed to land, and files on disk could predate this test.
     */
    private void assertRemoteStoreReceivedData() throws IOException {
        var stats = client().admin().cluster().prepareRemoteStoreStats(INDEX, "0").get();
        long uploadedBytes = 0;
        long uploadsSucceeded = 0;
        for (var shard : stats.getRemoteStoreStats()) {
            var seg = shard.getSegmentStats();
            uploadedBytes += seg.uploadBytesSucceeded;
            uploadsSucceeded += seg.totalUploadsSucceeded;
        }
        assertThat("remote store must report succeeded uploads", uploadsSucceeded, greaterThan(0L));
        assertThat("remote store must report uploaded bytes", uploadedBytes, greaterThan(0L));

        List<Path> blobs = listFiles(segmentRepoPath);
        long blobBytes = 0;
        for (Path p : blobs) {
            blobBytes += Files.size(p);
        }
        logger
            .info(
                "fdc-trace PHASE=remote-store-proof statsUploads={} statsBytes={} repoFiles={} repoBytes={}",
                uploadsSucceeded,
                uploadedBytes,
                blobs.size(),
                blobBytes
            );
        assertThat("the segment repository directory must contain blobs", blobs.size(), greaterThan(0));
        assertThat("the segment repository directory must contain bytes", blobBytes, greaterThan(0L));
    }

    private String remoteStoreStatsDump() {
        StringBuilder sb = new StringBuilder(512);
        var stats = client().admin().cluster().prepareRemoteStoreStats(INDEX, "0").get();
        for (var shard : stats.getRemoteStoreStats()) {
            var seg = shard.getSegmentStats();
            sb
                .append("  shard=")
                .append(shard.getShardRouting().shardId())
                .append(" primary=")
                .append(shard.getShardRouting().primary())
                .append('\n')
                .append("    uploadsStarted=")
                .append(seg.totalUploadsStarted)
                .append(" uploadsSucceeded=")
                .append(seg.totalUploadsSucceeded)
                .append(" uploadsFailed=")
                .append(seg.totalUploadsFailed)
                .append('\n')
                .append("    uploadBytesStarted=")
                .append(seg.uploadBytesStarted)
                .append(" uploadBytesSucceeded=")
                .append(seg.uploadBytesSucceeded)
                .append(" uploadBytesFailed=")
                .append(seg.uploadBytesFailed)
                .append('\n')
                .append("    bytesLag=")
                .append(seg.bytesLag)
                .append(" refreshTimeLagMs=")
                .append(seg.refreshTimeLagMs)
                .append(" localRefreshNumber=")
                .append(seg.localRefreshNumber)
                .append(" remoteRefreshNumber=")
                .append(seg.remoteRefreshNumber)
                .append('\n')
                .append("    transfer=")
                .append(seg.directoryFileTransferTrackerStats)
                .append('\n');
        }
        return sb.toString();
    }

    /** Repository directory tree with sizes - the on-disk evidence that bytes left the node. */
    private String repoTree(Path root, String label) throws IOException {
        StringBuilder sb = new StringBuilder(1024).append("  ").append(label).append(' ').append(root).append('\n');
        List<Path> files = listFiles(root);
        files.sort(Comparator.comparing(Path::toString));
        long total = 0;
        for (Path p : files) {
            long size = Files.size(p);
            total += size;
            sb.append("    ").append(root.relativize(p)).append("  ").append(size).append(" B\n");
        }
        sb.append("    TOTAL files=").append(files.size()).append(" bytes=").append(total).append('\n');
        return sb.toString();
    }

    private static List<Path> listFiles(Path root) throws IOException {
        if (Files.exists(root) == false) {
            return List.of();
        }
        try (Stream<Path> walk = Files.walk(root)) {
            return walk.filter(Files::isRegularFile).collect(Collectors.toCollection(ArrayList::new));
        }
    }

    // ------------------------------------------------------------------ metrics sampling

    /**
     * One line per instrument at a phase boundary: buffer pool + L1 + L2 from the plugin's own accounting, the
     * JVM's independent direct-buffer accounting, heap, and GC. The plugin numbers and the JVM numbers measure
     * the same off-heap blocks by different routes, so a disagreement between them is itself a finding — that
     * cross-check is why both are recorded rather than just the convenient one.
     *
     * <p>Deliberately NOT relying on the 10s {@code CryptoTelemetry} heartbeat: it cannot attribute phases that
     * are seconds apart, and a short test may produce no heartbeat at all.
     */
    private String sample(String label) {
        StringBuilder sb = new StringBuilder(512);
        sb.append("  label=").append(label).append('\n');
        sb.append("  plugin: ").append(CryptoDirectoryFactory.poolStateSnapshot()).append('\n');
        for (BufferPoolMXBean bp : ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class)) {
            sb
                .append("  jvmbuf[")
                .append(bp.getName())
                .append("] count=")
                .append(bp.getCount())
                .append(" used=")
                .append(bp.getMemoryUsed())
                .append(" capacity=")
                .append(bp.getTotalCapacity())
                .append('\n');
        }
        var mem = ManagementFactory.getMemoryMXBean();
        sb
            .append("  heap used=")
            .append(mem.getHeapMemoryUsage().getUsed())
            .append(" committed=")
            .append(mem.getHeapMemoryUsage().getCommitted())
            .append(" max=")
            .append(mem.getHeapMemoryUsage().getMax())
            .append('\n');
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            sb
                .append("  gc[")
                .append(gc.getName())
                .append("] count=")
                .append(gc.getCollectionCount())
                .append(" timeMs=")
                .append(gc.getCollectionTime())
                .append('\n');
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ plumbing

    /**
     * Raises (or resets) the store packages to DEBUG on the live cluster, so {@code fdc-debug} tracing covers a
     * measurement window and nothing else.
     *
     * <p>Why dynamic rather than {@code @TestLogging} or {@code -Dfdc.debug=true}: both are process-wide for the
     * whole test, so setup and teardown get fully traced too. On the peer-recovery track that produced a 365 MB
     * trace whose on-disk content never even reached the interesting window, because the Gradle worker then hung
     * for 24 minutes in output forwarding. It also puts tracing cost inside every timed region.
     *
     * <p>{@code FdcDebug.on} keys off {@code logger.isDebugEnabled()}, so flipping the level here enables routes,
     * call-site chains, per-block acquires, per-read access pattern and the timing accumulators for exactly the
     * window. Do NOT pass {@code -Dfdc.debug=true} with this test: it forces tracing on globally at INFO and
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

    private String indexSettingsDump() {
        return client().admin().indices().prepareGetSettings(INDEX).get().getIndexToSettings().toString();
    }

    private String catSegments() {
        return client().admin().indices().prepareSegments(INDEX).get().getIndices().toString();
    }

    private String catShardStore() {
        return client()
            .admin()
            .indices()
            .prepareStats(INDEX)
            .setStore(true)
            .setSegments(true)
            .setRefresh(true)
            .setFlush(true)
            .get()
            .getPrimaries()
            .toString();
    }

    private static long counterSum(Map<String, Long> counters, String... keys) {
        long total = 0;
        for (String k : keys) {
            total += counters.getOrDefault(k, 0L);
        }
        return total;
    }

    private static String renderCounters(Map<String, Long> counters) {
        StringBuilder sb = new StringBuilder(counters.size() * 48);
        counters.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(e -> {
            sb.append("  ").append(e.getKey()).append(" = ").append(e.getValue()).append('\n');
        });
        return sb.toString();
    }

    /** Kept so a slow first upload cannot fail the run on the default 10s assertBusy budget. */
    @SuppressWarnings("unused")
    private static final TimeValue GREEN_TIMEOUT = TimeValue.timeValueSeconds(60);
}
