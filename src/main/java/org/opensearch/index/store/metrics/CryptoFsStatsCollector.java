/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.monitor.fs.FsInfo;
import org.opensearch.monitor.fs.FsProbe;

/**
 * Node-level collector for physical (block-device / EBS) IO statistics.
 *
 * <p>Reads the same source the OpenSearch node stats API uses — {@code /proc/diskstats} via
 * {@link FsProbe} → {@link FsInfo.IoStats} — and turns the OS's cumulative-since-boot counters into
 * per-interval RATES by diffing successive snapshots. This is deliberately NODE-level and
 * time-series: device counters are shared by every shard/query/merge on the volume and CANNOT be
 * attributed to a single query, so they do not belong in the per-query profiler breakdown.
 *
 * <p>One instance per node (owned by {@link CryptoMetricsService}); {@link #sample()} is called on the
 * background telemetry cadence. {@code FsProbe} accepts a {@code null} FileCache (that argument is only
 * used for warm-tier space accounting; the IO stats are unaffected).
 *
 * <p>Modelled on the Juno Search Worker pattern (NodeStatsCollector diffing FsInfo.IoStats against a
 * previous snapshot); we keep the previous {@link FsInfo} here rather than passing OpenSearch's own.
 */
public final class CryptoFsStatsCollector {

    private static final Logger LOGGER = LogManager.getLogger(CryptoFsStatsCollector.class);

    private final FsProbe fsProbe;
    private FsInfo previous;
    private long previousTimestampMillis = -1L;

    /** Immutable snapshot of one sampling interval's device IO rates. */
    public static final class Sample {
        public final double readIops;        // read operations / sec
        public final double writeIops;       // write operations / sec
        public final double readKbPerSec;    // read throughput KB/s
        public final double writeKbPerSec;   // write throughput KB/s
        public final double readAwaitMs;     // avg ms per read op (Δreadtime / Δreadops)
        public final double utilPct;         // device busy %  (Δio_time / Δwall) * 100
        public final double readIoSizeKb;    // avg KB per read op (Δreadkb / Δreadops)
        public final long intervalMillis;

        Sample(
            double readIops,
            double writeIops,
            double readKbPerSec,
            double writeKbPerSec,
            double readAwaitMs,
            double utilPct,
            double readIoSizeKb,
            long intervalMillis
        ) {
            this.readIops = readIops;
            this.writeIops = writeIops;
            this.readKbPerSec = readKbPerSec;
            this.writeKbPerSec = writeKbPerSec;
            this.readAwaitMs = readAwaitMs;
            this.utilPct = utilPct;
            this.readIoSizeKb = readIoSizeKb;
            this.intervalMillis = intervalMillis;
        }

        @Override
        public String toString() {
            return String
                .format(
                    java.util.Locale.ROOT,
                    "FsIo[read_iops=%.1f write_iops=%.1f read_kb_s=%.1f write_kb_s=%.1f "
                        + "read_await_ms=%.3f util_pct=%.1f read_io_size_kb=%.1f interval_ms=%d]",
                    readIops,
                    writeIops,
                    readKbPerSec,
                    writeKbPerSec,
                    readAwaitMs,
                    utilPct,
                    readIoSizeKb,
                    intervalMillis
                );
        }
    }

    public CryptoFsStatsCollector(NodeEnvironment nodeEnvironment) {
        // fileCache = null: only used for warm-tier space accounting, not for IO stats.
        this.fsProbe = new FsProbe(nodeEnvironment, null);
    }

    /**
     * Take a snapshot and return the device IO rates for the interval since the previous call, or
     * {@code null} on the very first call (no baseline yet) or if IO stats are unavailable.
     * Totals are aggregated across all devices backing the node's data paths.
     */
    public synchronized Sample sample() {
        final FsInfo current;
        try {
            current = fsProbe.stats(previous);
        } catch (IOException | RuntimeException e) {
            LOGGER.warn("FsProbe stats failed; skipping FS IO sample", e);
            return null;
        }
        final long nowMillis = current.getTimestamp();
        final FsInfo.IoStats io = current.getIoStats();

        Sample result = null;
        if (previous != null && io != null && previousTimestampMillis > 0) {
            final long intervalMs = nowMillis - previousTimestampMillis;
            if (intervalMs > 0) {
                // FsInfo.IoStats totals are ALREADY per-interval deltas (FsProbe computes them from the
                // previous FsInfo we passed in). So getTotalReadOperations() etc. are Δ over this interval.
                final double secs = intervalMs / 1000.0;
                final long dReadOps = Math.max(0, io.getTotalReadOperations());
                final long dWriteOps = Math.max(0, io.getTotalWriteOperations());
                final long dReadKb = Math.max(0, io.getTotalReadKilobytes());
                final long dWriteKb = Math.max(0, io.getTotalWriteKilobytes());
                final long dReadTime = Math.max(0, io.getTotalReadTime());
                final long dIoTime = Math.max(0, io.getTotalIOTimeMillis());

                result = new Sample(
                    dReadOps / secs,
                    dWriteOps / secs,
                    dReadKb / secs,
                    dWriteKb / secs,
                    dReadOps > 0 ? (double) dReadTime / dReadOps : 0.0,
                    Math.min(100.0, (double) dIoTime / intervalMs * 100.0),
                    dReadOps > 0 ? (double) dReadKb / dReadOps : 0.0,
                    intervalMs
                );
            }
        }
        this.previous = current;
        this.previousTimestampMillis = nowMillis;
        return result;
    }
}
