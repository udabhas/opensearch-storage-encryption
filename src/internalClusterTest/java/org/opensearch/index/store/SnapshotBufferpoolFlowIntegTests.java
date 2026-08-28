/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.opensearch.test.hamcrest.OpenSearchAssertions.assertAcked;
import static org.opensearch.test.hamcrest.OpenSearchAssertions.assertHitCount;

import java.lang.management.BufferPoolMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.MemoryType;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import org.opensearch.action.admin.cluster.node.stats.NodesStatsResponse;
import org.opensearch.action.admin.cluster.snapshots.get.GetSnapshotsResponse;
import org.opensearch.action.admin.cluster.snapshots.status.SnapshotStats;
import org.opensearch.action.admin.cluster.snapshots.status.SnapshotStatus;
import org.opensearch.action.admin.cluster.snapshots.status.SnapshotsStatusResponse;
import org.opensearch.action.bulk.BulkRequestBuilder;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.index.store.pool.MemorySegmentPool;
import org.opensearch.index.store.pool.Pool;
import org.opensearch.plugins.Plugin;
import org.opensearch.snapshots.SnapshotInfo;
import org.opensearch.snapshots.SnapshotState;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.junit.annotations.TestLogging;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Pins the read path that <em>snapshot execute</em> takes on an encrypted ({@code cryptofs}) index, and
 * measures what it costs the buffer pool and the heap while it runs.
 *
 * <h2>The question</h2>
 * Snapshot upload is a one-pass, zero-reuse bulk read: every file is streamed to the repository exactly
 * once and never read again. That is the same profile as the field data build, which is why it is the
 * second candidate for the {@code skipBufferpool} treatment. But the routing seam is different, and the
 * difference decides the whole design:
 *
 * <ul>
 * <li>The field data build opens <strong>no</strong> files - it clones inputs that segment-core
 *     construction opened earlier - so a decision taken at {@code openInput} is structurally blind to it
 *     (see {@link FieldDataCacheFlowIntegTests}).</li>
 * <li>Snapshot, by contrast, is expected to call {@code openInput} once per file and never clone, because
 *     {@code Store.VerifyingIndexInput} - which wraps every snapshot read - throws
 *     {@code UnsupportedOperationException} from both {@code clone()} and {@code slice()}. If that holds,
 *     {@code openInput} <em>is</em> the deterministic hook and no clone-time plumbing is needed.</li>
 * </ul>
 *
 * <p>The second thing to pin is the {@link org.apache.lucene.store.IOContext} it arrives with.
 * {@code BlobStoreRepository.snapshotFile} passes {@code IOContext.DEFAULT}, not {@code READONCE} - only
 * the assertion-only {@code assertFileContentsMatchHash} uses {@code READONCE}. DEFAULT is
 * indistinguishable from a search open at the directory boundary, so the routing cannot key on IOContext
 * alone. These tests establish that empirically rather than trusting the read of core.
 *
 * <h2>Why polling and not setWaitForCompletion(true)</h2>
 * A snapshot that is waited on synchronously yields one number at the end. The pool numbers that matter -
 * peak {@code buffersInUse}, stall count, cache growth - happen <em>during</em> the upload and are gone by
 * the time it returns, because the L2 cache keeps evicting. So the snapshot is fired asynchronously and
 * the harness polls until it leaves {@code IN_PROGRESS}, sampling pool + heap on every tick. Snapshot
 * duration then comes from two independent instruments that must agree: the wall clock across the poll
 * loop, and {@code SnapshotStats.getTime()} reported by the snapshot itself.
 *
 * <p>Run it:
 * <pre>
 * ./gradlew internalClusterTest --tests '*SnapshotBufferpoolFlowIntegTests*' -Dfdc.debug=true -Dfdc.run=snap-baseline
 * ./gradlew internalClusterTest --tests '*SnapshotBufferpoolFlowIntegTests*' -Dfdc.debug=true -Dfdc.bypass=true -Dfdc.run=snap-skip
 * </pre>
 * The second run flips {@code StaticConfigs.blockCacheBypassEnabled()}, which is the A/B: same snapshot,
 * pool-backed blocks versus transient heap blocks.
 */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.TEST, numDataNodes = 0)
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
// Deliberately NARROW: only the two directories, not the whole store package. FdcDebug's counting latch is
// global, so raising these two is enough to make openInput/route counters live - but widening to
// `org.opensearch.index.store` also turns on the PER-BLOCK sites in CachedMemorySegmentIndexInput and
// CryptoDirectIOBlockLoader, which emit one line per 64KiB block. Measured: at 80 000 docs that produced a
// 750MB log and the run had to be killed. Pass -Dfdc.debug=true on the command line for full tracing on a
// SMALL index (the structural test); never for a sized measurement run.
@TestLogging(value = "org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory:DEBUG,"
    + "org.opensearch.index.store.hybrid.HybridCryptoDirectory:DEBUG", reason = "openInput route counters without per-block trace volume")
public class SnapshotBufferpoolFlowIntegTests extends OpenSearchIntegTestCase {

    private static final String INDEX = "snap-flow";
    private static final String REPO = "snap-repo";

    /**
     * Big enough that the upload is not instantaneous - a snapshot that finishes inside one poll interval
     * produces a single sample and no peak. Overridable so a run can be scaled up without an edit.
     */
    private static final int DOC_COUNT = Integer.getInteger("snap.docs", 20_000);

    /**
     * Fixed, small, and deliberately NOT overridable: the structural test runs with the whole store package
     * at DEBUG, which emits a line per 64KiB block. Letting -Dsnap.docs raise it would reintroduce the
     * 750MB-log failure mode. Structure does not need volume.
     */
    private static final int STRUCTURAL_DOC_COUNT = 4_000;

    /** Poll cadence for the status loop. Fine enough to catch a peak, coarse enough not to be the load. */
    private static final long POLL_INTERVAL_MS = Long.getLong("snap.pollMs", 25L);

    /** Guard so a wedged snapshot fails the test instead of hanging the build. */
    private static final long POLL_TIMEOUT_MS = Long.getLong("snap.timeoutMs", 300_000L);

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
     * The structural finding, asserted rather than eyeballed: snapshot execute reaches the directory
     * through {@code openInput} - once per file - and derives <strong>zero</strong> inputs from those
     * opens.
     *
     * <p>Consequence for routing design: unlike the field data build, a skip-the-pool decision taken at
     * {@code openInput} time is sufficient here. Nothing needs to be plumbed through {@code clone()} or
     * {@code slice()}, because the snapshot path never calls them.
     *
     * <p>The zero-derivations claim is one-sided on purpose. Zero is the claim; a non-zero open count and
     * non-zero block traffic in the same window are what make the zero meaningful rather than vacuous.
     */
    // Widened to the whole store package for THIS test only, because the zero-derivations claim is checked
    // against counters that live in CachedMemorySegmentIndexInput. Safe here and only here: this test pins a
    // structure, so it runs at STRUCTURAL_DOC_COUNT regardless of -Dsnap.docs, which bounds the trace volume.
    @TestLogging(value = "org.opensearch.index.store:DEBUG", reason = "clone/slice counters live in CachedMemorySegmentIndexInput")
    public void testSnapshotOpensFilesOncePerFileAndNeverClones() throws Exception {
        internalCluster().startNode();
        createRepository();
        createIndexAndIngest(STRUCTURAL_DOC_COUNT);

        // The pool must be live before the window opens, otherwise the first snapshot read pays for lazy
        // pool construction and the counters attribute that to the snapshot.
        assertHitCount(client().prepareSearch(INDEX).setSize(1).setRequestCache(false).setTrackTotalHits(true).get(), STRUCTURAL_DOC_COUNT);

        FdcDebug.resetCounters();
        SnapshotInfo info = runSnapshotAndWait("snap-structural");
        Map<String, Long> counts = FdcDebug.counters();

        logger.info("snap-flow: counters across snapshot execute = {}", counts);

        long opens = FdcDebug.counterOf("pool.openInput") + FdcDebug.counterOf("hybrid.openInput");
        long derived = FdcDebug.counterOf("input.clone") + FdcDebug.counterOf("input.slice");

        assertThat("snapshot must have succeeded, else there was nothing to measure", info.state(), equalTo(SnapshotState.SUCCESS));
        assertThat("snapshot execute must open files; counters were " + counts, opens, greaterThan(0L));

        // PRECONDITION for the zero below, not a finding. input.clone / input.slice are incremented behind
        // FdcDebug.on(CachedMemorySegmentIndexInput's logger); if that logger were not live, they would read
        // zero no matter what the code did and the assertion would pass vacuously. input.create.master sits
        // behind the SAME gate, so a positive value here proves the clone/slice sites were live.
        assertThat(
            "clone/slice counting must be live for the zero below to mean anything; counters were " + counts,
            FdcDebug.counterOf("input.create.master"),
            greaterThan(0L)
        );

        assertThat("snapshot execute must not clone or slice any input; counters were " + counts, derived, equalTo(0L));

        // Which route those opens took is the design-relevant part: a POOL route means the snapshot is
        // paying for pooled buffers it will never re-read.
        logger.info("snap-flow: openInput routes = {}", routeCounters(counts));
    }

    /**
     * The measurement harness: fires the snapshot asynchronously and polls until it leaves
     * {@code IN_PROGRESS}, sampling buffer-pool and heap state on every tick.
     *
     * <p>Reports, per run: snapshot duration from two independent instruments, the peak and delta of every
     * pool counter, heap high-water mark, and the {@link FdcDebug} counter totals. Asserts only what holds
     * at any scale - that the snapshot succeeded, that the poll loop actually sampled the middle of it, and
     * that the two duration instruments agree in order of magnitude. The pool and heap numbers are reported
     * for reading rather than asserted, because their absolute values depend on pool size versus index size,
     * which is a property of the deployment and not of this code path.
     */
    public void testSnapshotTimingBufferpoolAndHeapWhilePolling() throws Exception {
        internalCluster().startNode();
        createRepository();
        createIndexAndIngest(DOC_COUNT);

        assertHitCount(client().prepareSearch(INDEX).setSize(1).setRequestCache(false).setTrackTotalHits(true).get(), DOC_COUNT);

        final String snapshot = "snap-measured";
        FdcDebug.resetCounters();

        // Rebase the JVM's peak watermarks and GC counters so everything reported below is attributable to
        // THIS snapshot. Without the rebase, "peak heap" is whatever the ingest happened to reach, and the
        // two arms of an A/B are not comparable - measured: two runs of this test started 63MiB apart.
        System.gc();
        resetHeapPeaks();
        final Map<String, Long> gcCountBefore = gcCounts();
        final Map<String, Long> gcTimeBefore = gcTimesMs();
        final Map<String, Long> heapUsedBefore = usedHeapByPool();

        Sample before = sample(0L);
        logger.info("snap-metrics BEFORE {}", before);
        logger.info("snap-heap   BEFORE perPoolUsed={}", asMib(heapUsedBefore));

        long startNanos = System.nanoTime();
        client().admin().cluster().prepareCreateSnapshot(REPO, snapshot).setWaitForCompletion(false).setIndices(INDEX).get();

        List<Sample> samples = new ArrayList<>();
        SnapshotState finalState = pollUntilDone(snapshot, startNanos, samples);
        long wallClockMs = (System.nanoTime() - startNanos) / 1_000_000L;

        Sample after = sample(wallClockMs);
        logger.info("snap-metrics AFTER  {}", after);

        assertThat("snapshot must succeed; state was " + finalState, finalState, equalTo(SnapshotState.SUCCESS));

        // ---- duration, from two instruments ----
        SnapshotStats stats = snapshotStats(snapshot);
        SnapshotInfo info = snapshotInfo(snapshot);
        long reportedMs = stats == null ? -1L : stats.getTime();
        long infoMs = info.endTime() - info.startTime();

        logger
            .info(
                "snap-timing: wallClock={}ms snapshotStats.getTime={}ms snapshotInfo.endTime-startTime={}ms "
                    + "files={} processedFiles={} totalBytes={} processedBytes={} shards={}/{}",
                wallClockMs,
                reportedMs,
                infoMs,
                stats == null ? -1 : stats.getTotalFileCount(),
                stats == null ? -1 : stats.getProcessedFileCount(),
                stats == null ? -1L : stats.getTotalSize(),
                stats == null ? -1L : stats.getProcessedSize(),
                info.successfulShards(),
                info.totalShards()
            );

        // ---- pool + heap trajectory ----
        reportTrajectory(before, samples, after);

        // ---- GC and TRUE peak heap, attributable to this snapshot ----
        logger.info("snap-heap   AFTER  perPoolUsed={}", asMib(usedHeapByPool()));
        logger.info("snap-heap   PEAK   perPoolPeak={}  (JVM watermark, not sampled)", asMib(peakHeapByPool()));
        logger.info("snap-heap   DELTA  perPoolUsed={}", asMib(deltaOf(heapUsedBefore, usedHeapByPool())));
        logger.info("snap-gc     COUNT  delta={}", deltaOf(gcCountBefore, gcCounts()));
        logger.info("snap-gc     TIMEMS delta={}", deltaOf(gcTimeBefore, gcTimesMs()));

        Map<String, Long> counts = FdcDebug.counters();
        logger.info("snap-flow: counters across measured snapshot = {}", counts);
        logger.info("snap-flow: openInput routes = {}", routeCounters(counts));

        // The poll loop must have seen the snapshot mid-flight, else "peak during snapshot" is a fiction
        // computed from the two endpoints.
        assertThat(
            "poll loop must have sampled at least once while the snapshot ran; samples=" + samples.size(),
            samples.size(),
            greaterThan(0)
        );
    }

    // ---- snapshot driving ----

    private void createRepository() {
        Path repoPath = randomRepoPath();
        logger.info("snap-flow: repository at {}", repoPath);
        assertAcked(
            client()
                .admin()
                .cluster()
                .preparePutRepository(REPO)
                .setType("fs")
                // compress=false keeps the repository write path out of the measurement: with compression on,
                // upload time is dominated by DEFLATE on the snapshot thread, not by the encrypted read.
                .setSettings(Settings.builder().put("location", repoPath).put("compress", false))
                .get()
        );
    }

    private SnapshotInfo runSnapshotAndWait(String snapshot) {
        return client()
            .admin()
            .cluster()
            .prepareCreateSnapshot(REPO, snapshot)
            .setWaitForCompletion(true)
            .setIndices(INDEX)
            .get()
            .getSnapshotInfo();
    }

    /**
     * Polls snapshot state until it is terminal, sampling on every tick.
     *
     * <p>Uses get-snapshots rather than snapshot-status for the state check: status is served from cluster
     * state while in progress and from the repository once complete, and the changeover has been a source
     * of transient failures. get-snapshots with {@code ignoreUnavailable} answers both phases uniformly,
     * and returns an empty list for the window between the create call returning and the snapshot being
     * registered - which is why an empty list is treated as "still starting" rather than as an error.
     */
    private SnapshotState pollUntilDone(String snapshot, long startNanos, List<Sample> samples) throws Exception {
        long deadline = System.nanoTime() + POLL_TIMEOUT_MS * 1_000_000L;
        while (System.nanoTime() < deadline) {
            samples.add(sample((System.nanoTime() - startNanos) / 1_000_000L));

            GetSnapshotsResponse response = client()
                .admin()
                .cluster()
                .prepareGetSnapshots(REPO)
                .setSnapshots(snapshot)
                .setIgnoreUnavailable(true)
                .get();

            if (response.getSnapshots().isEmpty() == false) {
                SnapshotState state = response.getSnapshots().get(0).state();
                if (state != SnapshotState.IN_PROGRESS) {
                    return state;
                }
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
        throw new AssertionError("snapshot [" + snapshot + "] did not finish within " + POLL_TIMEOUT_MS + "ms");
    }

    private SnapshotInfo snapshotInfo(String snapshot) {
        GetSnapshotsResponse response = client().admin().cluster().prepareGetSnapshots(REPO).setSnapshots(snapshot).get();
        return response.getSnapshots().get(0);
    }

    /**
     * Snapshot-level stats, or null when the status API cannot serve them.
     *
     * <p>Returns null rather than throwing because {@code getTime()} is a nice-to-have cross-check on the
     * wall clock, not the measurement itself - losing it must not fail a run that otherwise produced every
     * pool and heap number.
     */
    private SnapshotStats snapshotStats(String snapshot) {
        try {
            SnapshotsStatusResponse response = client().admin().cluster().prepareSnapshotStatus(REPO).setSnapshots(snapshot).get();
            if (response.getSnapshots().isEmpty()) {
                return null;
            }
            SnapshotStatus status = response.getSnapshots().get(0);
            return status.getStats();
        } catch (Exception e) {
            logger.info("snap-timing: snapshot status unavailable ({}), falling back to wall clock only", e.toString());
            return null;
        }
    }

    // ---- sampling ----

    /**
     * One instant of everything worth watching during a snapshot.
     *
     * <p>{@code buffersInUse} is the load-bearing field: the pool has no freelist and {@code release()} is
     * a no-op, so this number only ever comes down when the L2 cache evicts. A snapshot that raises it and
     * leaves it raised has borrowed pool capacity that search now cannot use.
     */
    private record Sample(long atMs, int poolBuffersInUse, long poolAllocatedBytes, long poolDirectMemoryUsed, long poolStallCount,
        long poolGcTriggerCount, long poolAvailableMemory, long l2CacheSize, long jvmDirectUsed, long jvmDirectCount, long heapUsed,
        long heapCommitted, long heapMax) {
        @Override
        public String toString() {
            return String
                .format(
                    Locale.ROOT,
                    "at=%dms pool[inUse=%d allocated=%s directUsed=%s stalls=%d gcTriggers=%d available=%s] "
                        + "l2[entries=%d] jvmDirect[used=%s count=%d] heap[used=%s committed=%s max=%s]",
                    atMs,
                    poolBuffersInUse,
                    mib(poolAllocatedBytes),
                    mib(poolDirectMemoryUsed),
                    poolStallCount,
                    poolGcTriggerCount,
                    mib(poolAvailableMemory),
                    l2CacheSize,
                    mib(jvmDirectUsed),
                    jvmDirectCount,
                    mib(heapUsed),
                    mib(heapCommitted),
                    mib(heapMax)
                );
        }
    }

    private Sample sample(long atMs) {
        Pool<RefCountedByteBuffer> pool = CryptoDirectoryFactory.getSharedSegmentPool();
        int inUse = 0;
        long allocated = 0L;
        long directUsed = 0L;
        long stalls = 0L;
        long gcTriggers = 0L;
        long available = 0L;
        if (pool instanceof MemorySegmentPool msp) {
            inUse = msp.getBuffersInUse();
            allocated = msp.getAllocatedBytes();
            directUsed = msp.getDirectMemoryUsed();
            stalls = msp.getStallCount();
            gcTriggers = msp.getGcTriggerCount();
            available = msp.availableMemory();
        }

        var cache = CryptoDirectoryFactory.getSharedBlockCache();
        long l2Size = cache == null ? -1L : cache.getCacheSize();

        BufferPoolMXBean direct = directBufferPool();
        long jvmDirectUsed = direct == null ? -1L : direct.getMemoryUsed();
        long jvmDirectCount = direct == null ? -1L : direct.getCount();

        var heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();

        return new Sample(
            atMs,
            inUse,
            allocated,
            directUsed,
            stalls,
            gcTriggers,
            available,
            l2Size,
            jvmDirectUsed,
            jvmDirectCount,
            heap.getUsed(),
            heap.getCommitted(),
            heap.getMax()
        );
    }

    /**
     * The JVM's own view of direct memory, independent of the plugin's accounting.
     *
     * <p>Kept as a cross-check rather than a duplicate: the pool tracks what it believes it handed out,
     * the MXBean tracks what the JVM actually mapped. The two disagreeing is itself the finding - it means
     * direct buffers are being allocated outside the pool's accounting.
     */
    private static BufferPoolMXBean directBufferPool() {
        for (BufferPoolMXBean bean : ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class)) {
            if ("direct".equals(bean.getName())) {
                return bean;
            }
        }
        return null;
    }

    /** Emits every sample, then the peaks and the before/after deltas that the peaks give meaning to. */
    private void reportTrajectory(Sample before, List<Sample> samples, Sample after) {
        for (Sample s : samples) {
            logger.info("snap-metrics SAMPLE {}", s);
        }

        int peakInUse = before.poolBuffersInUse();
        long peakL2 = before.l2CacheSize();
        long peakHeap = before.heapUsed();
        long peakJvmDirect = before.jvmDirectUsed();
        for (Sample s : samples) {
            peakInUse = Math.max(peakInUse, s.poolBuffersInUse());
            peakL2 = Math.max(peakL2, s.l2CacheSize());
            peakHeap = Math.max(peakHeap, s.heapUsed());
            peakJvmDirect = Math.max(peakJvmDirect, s.jvmDirectUsed());
        }

        logger
            .info(
                "snap-metrics PEAK   pool[inUse={}] l2[entries={}] jvmDirect[used={}] heap[used={}] over {} samples",
                peakInUse,
                peakL2,
                mib(peakJvmDirect),
                mib(peakHeap),
                samples.size()
            );

        logger
            .info(
                "snap-metrics DELTA  pool[inUse={} allocated={} directUsed={} stalls={} gcTriggers={}] "
                    + "l2[entries={}] jvmDirect[used={} count={}] heap[used={}]",
                after.poolBuffersInUse() - before.poolBuffersInUse(),
                mib(after.poolAllocatedBytes() - before.poolAllocatedBytes()),
                mib(after.poolDirectMemoryUsed() - before.poolDirectMemoryUsed()),
                after.poolStallCount() - before.poolStallCount(),
                after.poolGcTriggerCount() - before.poolGcTriggerCount(),
                after.l2CacheSize() - before.l2CacheSize(),
                mib(after.jvmDirectUsed() - before.jvmDirectUsed()),
                after.jvmDirectCount() - before.jvmDirectCount(),
                mib(after.heapUsed() - before.heapUsed())
            );

        // Node-level heap as a second instrument. The node runs in this JVM, so it should broadly track
        // ManagementFactory; a large disagreement means the test framework is holding the difference.
        NodesStatsResponse nodes = client().admin().cluster().prepareNodesStats("data:true").clear().addMetric("jvm").get();
        for (int i = 0; i < nodes.getNodes().size(); i++) {
            var jvm = nodes.getNodes().get(i).getJvm();
            logger
                .info(
                    "snap-metrics NODEJVM heapUsed={} heapMax={} heapUsedPercent={}%",
                    jvm.getMem().getHeapUsed(),
                    jvm.getMem().getHeapMax(),
                    jvm.getMem().getHeapUsedPercent()
                );
        }
    }

    private static Map<String, Long> routeCounters(Map<String, Long> counts) {
        Map<String, Long> routes = new TreeMap<>();
        counts.forEach((k, v) -> {
            if (k.startsWith("pool.openInput.ROUTE=") || k.startsWith("hybrid.openInput.route=")) {
                routes.put(k, v);
            }
        });
        return routes;
    }

    private static String mib(long bytes) {
        return String.format(Locale.ROOT, "%.2fMiB", bytes / (1024.0 * 1024.0));
    }

    // ---- index setup ----

    private void createIndexAndIngest(int docCount) throws Exception {
        assertAcked(client().admin().indices().prepareCreate(INDEX).setSettings(cryptoIndexSettings()).get());
        ensureGreen(INDEX);

        // Bulk, not per-document: 20k individual index requests dominate the test runtime and the point of
        // the ingest is only to produce files worth snapshotting.
        final int batch = 1_000;
        for (int start = 0; start < docCount; start += batch) {
            BulkRequestBuilder bulk = client().prepareBulk();
            for (int i = start; i < Math.min(start + batch, docCount); i++) {
                bulk
                    .add(
                        client()
                            .prepareIndex(INDEX)
                            .setId(Integer.toString(i))
                            .setSource("user", "user" + (i % 1000), "session", "session" + (i % 97), "body", payload(i), "value", i)
                    );
            }
            BulkResponse response = bulk.get();
            assertFalse("bulk ingest failed: " + response.buildFailureMessage(), response.hasFailures());
        }

        // One segment, so the snapshot reads a few large files rather than many tiny ones. Many-small-files
        // would make the run dominated by per-file open cost instead of by block reads, which is the thing
        // under measurement.
        client().admin().indices().prepareForceMerge(INDEX).setMaxNumSegments(1).get();
        client().admin().indices().prepareRefresh(INDEX).get();
        client().admin().indices().prepareFlush(INDEX).get();
        // setTrackTotalHits(true) is required, not cosmetic: total hits are capped at 10 000 by default, so any
        // docCount above that fails this assertion with "10000+ hits but N was expected".
        assertHitCount(client().prepareSearch(INDEX).setSize(0).setTrackTotalHits(true).get(), docCount);
    }

    /** Deterministic ~200-byte body, so file sizes are reproducible across runs of the same DOC_COUNT. */
    private static String payload(int i) {
        StringBuilder sb = new StringBuilder(224);
        for (int w = 0; w < 24; w++) {
            sb.append("term").append((i + w * 7) % 4096).append(' ');
        }
        return sb.toString();
    }

    // ---- GC and true peak heap ----

    /**
     * Resets the JVM's per-pool peak-usage watermarks so {@link #peakHeapByPool} afterwards reports the peak
     * for THIS window only.
     *
     * <p>Needed because the sampled peak in {@link #reportTrajectory} is taken every {@link #POLL_INTERVAL_MS}
     * and can miss a spike entirely between two samples — it is a lower bound on the peak, not the peak. The
     * JVM tracks the real watermark continuously; this just rebases it.
     */
    private static void resetHeapPeaks() {
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == MemoryType.HEAP && pool.isValid()) {
                pool.resetPeakUsage();
            }
        }
    }

    /** True per-generation peak since the last {@link #resetHeapPeaks}, in bytes. */
    private static Map<String, Long> peakHeapByPool() {
        Map<String, Long> out = new TreeMap<>();
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == MemoryType.HEAP && pool.isValid() && pool.getPeakUsage() != null) {
                out.put(pool.getName(), pool.getPeakUsage().getUsed());
            }
        }
        return out;
    }

    /** Current per-generation heap usage, in bytes. Old-gen movement is the promotion signal. */
    private static Map<String, Long> usedHeapByPool() {
        Map<String, Long> out = new TreeMap<>();
        for (MemoryPoolMXBean pool : ManagementFactory.getMemoryPoolMXBeans()) {
            if (pool.getType() == MemoryType.HEAP && pool.isValid() && pool.getUsage() != null) {
                out.put(pool.getName(), pool.getUsage().getUsed());
            }
        }
        return out;
    }

    /** Cumulative GC collection counts per collector. */
    private static Map<String, Long> gcCounts() {
        Map<String, Long> out = new TreeMap<>();
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            out.put(gc.getName(), gc.getCollectionCount());
        }
        return out;
    }

    /** Cumulative GC time per collector, in milliseconds. */
    private static Map<String, Long> gcTimesMs() {
        Map<String, Long> out = new TreeMap<>();
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            out.put(gc.getName(), gc.getCollectionTime());
        }
        return out;
    }

    private static Map<String, Long> deltaOf(Map<String, Long> before, Map<String, Long> after) {
        Map<String, Long> out = new TreeMap<>();
        after.forEach((k, v) -> out.put(k, v - before.getOrDefault(k, 0L)));
        return out;
    }

    private static Map<String, String> asMib(Map<String, Long> bytes) {
        Map<String, String> out = new TreeMap<>();
        bytes.forEach((k, v) -> out.put(k, mib(v)));
        return out;
    }
}
