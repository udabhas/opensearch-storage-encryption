/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import org.opensearch.index.store.pool.SegmentType;
import org.opensearch.telemetry.metrics.Counter;
import org.opensearch.telemetry.metrics.Histogram;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.telemetry.metrics.tags.Tags;

import lombok.NonNull;

/**
 * Registry for crypto operations metrics and tracing.
 * Provides centralized access to telemetry data collection for encryption/decryption operations.
 */
public class CryptoMetricsService {
    private static volatile CryptoMetricsService instance;
    private final MetricsRegistry metricsRegistry;
    private final Histogram poolStatsHistogram;
    private final Histogram cacheStatsHistogram;
    private final Histogram throttleStatsHistogram;
    private final Histogram memoryStatsHistogram;
    private final Histogram l1StatsHistogram;
    private final Histogram kmsCallHistogram;
    private final Counter errorCounter;
    private final Counter throttleEngagedCounter;
    private final Counter degradedReadCounter;

    // Metric names
    private static final String POOL_STATS_NAME = "crypto.pool.stats";
    private static final String CACHE_STATS_NAME = "crypto.cache.stats";
    private static final String ERROR_COUNTER_NAME = "crypto.error.total";
    private static final String THROTTLE_STATS_NAME = "crypto.pool.throttle.stats";
    private static final String MEMORY_STATS_NAME = "crypto.pool.memory.stats";
    private static final String L1_STATS_NAME = "crypto.l1.stats";
    private static final String KMS_CALL_NAME = "crypto.kms.call";
    private static final String THROTTLE_ENGAGED_COUNTER_NAME = "crypto.pool.throttle.engaged.total";
    private static final String DEGRADED_READ_COUNTER_NAME = "crypto.read.degraded.total";

    // Metric descriptions
    private static final String POOL_STATS_DESC = "Crypto Pool statistics";
    private static final String CACHE_STATS_DESC = "Crypto Cache statistics";
    private static final String ERROR_COUNTER_DESC = "Total crypto operation errors";
    private static final String THROTTLE_STATS_DESC = "Crypto Pool back-pressure throttle/stall/gc statistics";
    private static final String MEMORY_STATS_DESC =
        "Crypto Pool memory-pressure causal factors (direct/os headroom, zombie bytes, alloc/reclaim rate) — the throttle post-mortem set";
    private static final String L1_STATS_DESC =
        "Crypto L1 (RadixBlockTable) cache effectiveness (hits/misses/hit_rate/evictions/table_count)";
    private static final String THROTTLE_ENGAGED_COUNTER_DESC =
        "Count of throttle clear->engaged transitions (low-latency RED-risk signal)";
    private static final String DEGRADED_READ_COUNTER_DESC =
        "Count of degraded (uncached, heap-fallback) block reads under pool exhaustion";
    private static final String KMS_CALL_DESC =
        "KMS call count + latency (tag op=generate_data_key|decrypt, result=ok|transient|error; transient=throttle/rate-limit/network per KeyCacheException.classify) — KMS throttling is a known latency cause";

    // Throttle-arm tag
    private static final String THROTTLE_ARM_TAG = "throttle_arm";

    // Units
    private static final String COUNT_UNIT = "count";
    private static final String MS_UNIT = "ms";

    // Tag names
    private static final String ERROR_TYPE_TAG = "error_type";
    private static final String STAT_TYPE_TAG = "stat_type";
    private static final String INDEX_NAME = "index_name";
    private static final String OP_TAG = "op";
    private static final String RESULT_TAG = "result";

    // Error message
    private static final String NOT_INITIALIZED_ERROR = "CryptoMetricsRegistry not initialized.";

    /**
     * Private constructor for singleton pattern.
     * @param metricsRegistry the metrics registry for collecting metrics
     */
    private CryptoMetricsService(@NonNull MetricsRegistry metricsRegistry) {
        this.metricsRegistry = metricsRegistry;
        this.errorCounter = createCounter(ERROR_COUNTER_NAME, ERROR_COUNTER_DESC, COUNT_UNIT);
        this.poolStatsHistogram = createHistogram(POOL_STATS_NAME, POOL_STATS_DESC, COUNT_UNIT);
        this.cacheStatsHistogram = createHistogram(CACHE_STATS_NAME, CACHE_STATS_DESC, COUNT_UNIT);
        this.throttleStatsHistogram = createHistogram(THROTTLE_STATS_NAME, THROTTLE_STATS_DESC, COUNT_UNIT);
        this.memoryStatsHistogram = createHistogram(MEMORY_STATS_NAME, MEMORY_STATS_DESC, COUNT_UNIT);
        this.l1StatsHistogram = createHistogram(L1_STATS_NAME, L1_STATS_DESC, COUNT_UNIT);
        this.throttleEngagedCounter = createCounter(THROTTLE_ENGAGED_COUNTER_NAME, THROTTLE_ENGAGED_COUNTER_DESC, COUNT_UNIT);
        this.degradedReadCounter = createCounter(DEGRADED_READ_COUNTER_NAME, DEGRADED_READ_COUNTER_DESC, COUNT_UNIT);
        this.kmsCallHistogram = createHistogram(KMS_CALL_NAME, KMS_CALL_DESC, MS_UNIT);
    }

    /**
     * Initializes the singleton instance.
     * @param metricsRegistry the metrics registry for collecting metrics
     */
    public static synchronized void initialize(@NonNull MetricsRegistry metricsRegistry) {
        if (instance == null) {
            instance = new CryptoMetricsService(metricsRegistry);
        }
    }

    /**
     * Gets the singleton instance.
     * @return the CryptoMetricsRegistry instance
     * @throws IllegalStateException if not initialized
     */
    public static CryptoMetricsService getInstance() {
        if (instance == null) {
            throw new IllegalStateException(NOT_INITIALIZED_ERROR);
        }
        return instance;
    }

    /**
     * Records pool statistics as separate time series.
     * @param maxSegments maximum segments
     * @param allocated allocated segments
     * @param free free segments
     * @param utilization utilization percentage (0-100)
     * @param allocation allocation percentage (0-100)
     */
    public void recordPoolStats(SegmentType segmentType, int maxSegments, int allocated, int free, double utilization, double allocation) {
        if (poolStatsHistogram == null)
            return;

        Tags baseTags = Tags.create().addTag("segment_type", segmentType.getValue());
        poolStatsHistogram.record(maxSegments, baseTags.addTag(STAT_TYPE_TAG, "max"));
        poolStatsHistogram.record(allocated, baseTags.addTag(STAT_TYPE_TAG, "allocated"));
        poolStatsHistogram.record(free, baseTags.addTag(STAT_TYPE_TAG, "free"));
        poolStatsHistogram.record(utilization, baseTags.addTag(STAT_TYPE_TAG, "utilization"));
        poolStatsHistogram.record(allocation, baseTags.addTag(STAT_TYPE_TAG, "allocation"));
    }

    /**
     * Records the pool back-pressure throttle state as a time series. The RED-shard-prevention mechanism
     * (throttle / stall / gc-hint) is otherwise only reachable via getters and log lines, which cannot be
     * dashboarded or alarmed on directly. Emitted on the telemetry tick.
     *
     * <p>{@code stall_count} and {@code gc_trigger_count} are PER-INTERVAL deltas (this telemetry tick minus
     * the last), NOT lifetime cumulative counts — so the dashboard is a plain {@code avg}/{@code sum} with no
     * {@code derivative()} (which mis-handles JVM-restart counter resets). {@code throttle_engaged} is an
     * instantaneous 0/1 gauge. See {@code MemorySegmentPool#recordStats}.
     *
     * @param throttleEngaged 1 if the throttle is currently engaged, else 0 (instantaneous gauge)
     * @param throttleArm which check engaged ("direct", "os", "direct+os", or "" when clear) — emitted as a tag
     * @param stallCount allocation stalls in this interval (delta)
     * @param gcTriggerCount System.gc() relief hints issued in this interval (delta)
     */
    public void recordThrottleStats(int throttleEngaged, String throttleArm, long stallCount, long gcTriggerCount) {
        if (throttleStatsHistogram == null)
            return;

        Tags armTags = Tags.create().addTag(THROTTLE_ARM_TAG, throttleArm == null || throttleArm.isEmpty() ? "none" : throttleArm);
        throttleStatsHistogram.record(throttleEngaged, armTags.addTag(STAT_TYPE_TAG, "throttle_engaged"));
        throttleStatsHistogram.record(stallCount, Tags.create().addTag(STAT_TYPE_TAG, "stall_count"));
        throttleStatsHistogram.record(gcTriggerCount, Tags.create().addTag(STAT_TYPE_TAG, "gc_trigger_count"));
    }

    /**
     * Records the memory-pressure causal factors — the "why did the pool throttle" post-mortem set.
     * These are the leading indicators (direct-memory headroom, OS-free headroom, GC-pending zombie
     * bytes, and the allocation/reclamation rate trajectory) that are otherwise only visible in log
     * lines, so an incident could see <em>that</em> the pool throttled but not the memory trajectory
     * that got it there. All emitted as one histogram, one {@code stat_type} series each, on the
     * telemetry tick.
     *
     * @param directUsedBytes    off-heap bytes in use (BufferPoolMXBean), or -1 if unavailable
     * @param directMaxBytes     -XX:MaxDirectMemorySize in bytes, or 0 if unset
     * @param directHeadroomBytes directMax - directUsed (distance to the direct-arm throttle), or -1
     * @param zombieBytes        GC-pending buffers (buffersInUse - cacheEntries) in bytes; the primary throttle cause
     * @param osFreeBytes        /proc/meminfo MemAvailable in bytes, or -1 if unavailable
     * @param osFreeHeadroomBytes osFree - osFreeThreshold (distance to the os-arm throttle), or -1
     * @param allocationRateBytesPerSec 1s allocation rate (pool filling velocity)
     * @param reclamationRateBytesPerSec 1s reclamation rate (Cleaner drain velocity)
     * @param consecutiveThrottledTicks how many consecutive monitor ticks the throttle has stayed engaged (stuck-throttle / RED precursor)
     */
    public void recordMemoryStats(
        long directUsedBytes,
        long directMaxBytes,
        long directHeadroomBytes,
        long zombieBytes,
        long osFreeBytes,
        long osFreeHeadroomBytes,
        long allocationRateBytesPerSec,
        long reclamationRateBytesPerSec,
        int consecutiveThrottledTicks
    ) {
        if (memoryStatsHistogram == null)
            return;

        memoryStatsHistogram.record(directUsedBytes, Tags.create().addTag(STAT_TYPE_TAG, "direct_used_bytes"));
        memoryStatsHistogram.record(directMaxBytes, Tags.create().addTag(STAT_TYPE_TAG, "direct_max_bytes"));
        memoryStatsHistogram.record(directHeadroomBytes, Tags.create().addTag(STAT_TYPE_TAG, "direct_headroom_bytes"));
        memoryStatsHistogram.record(zombieBytes, Tags.create().addTag(STAT_TYPE_TAG, "zombie_bytes"));
        memoryStatsHistogram.record(osFreeBytes, Tags.create().addTag(STAT_TYPE_TAG, "os_free_bytes"));
        memoryStatsHistogram.record(osFreeHeadroomBytes, Tags.create().addTag(STAT_TYPE_TAG, "os_free_headroom_bytes"));
        memoryStatsHistogram.record(allocationRateBytesPerSec, Tags.create().addTag(STAT_TYPE_TAG, "allocation_rate_bytes_per_sec"));
        memoryStatsHistogram.record(reclamationRateBytesPerSec, Tags.create().addTag(STAT_TYPE_TAG, "reclamation_rate_bytes_per_sec"));
        memoryStatsHistogram.record(consecutiveThrottledTicks, Tags.create().addTag(STAT_TYPE_TAG, "consecutive_throttled_ticks"));
    }

    /**
     * Records L1 (RadixBlockTable) cache effectiveness — a dropping L1 hit rate is the leading indicator of
     * cold-segment decrypt latency, and is otherwise not observable. Counts and the
     * derived hit-rate are PER-INTERVAL deltas (this telemetry tick minus the last), NOT lifetime cumulative
     * totals — so the dashboard is a plain {@code avg(value)} with no {@code derivative()} (which mis-handles
     * JVM-restart counter resets and cannot compute a per-interval hit-rate across separate series).
     * {@code tableCount} is an instantaneous gauge. See {@code RadixBlockTableRegistry#recordStats}.
     *
     * @param hits       L1 hits in this interval
     * @param misses     L1 misses in this interval
     * @param hitRate    hit rate percentage over this interval (0-100)
     * @param evictions  L1 evictions in this interval (driven by L2 eviction callback)
     * @param tableCount number of files with an active L1 table (instantaneous gauge, NOT a delta)
     */
    public void recordL1Stats(long hits, long misses, double hitRate, long evictions, int tableCount) {
        if (l1StatsHistogram == null)
            return;

        l1StatsHistogram.record(hits, Tags.create().addTag(STAT_TYPE_TAG, "hits"));
        l1StatsHistogram.record(misses, Tags.create().addTag(STAT_TYPE_TAG, "misses"));
        l1StatsHistogram.record(hitRate, Tags.create().addTag(STAT_TYPE_TAG, "hit_rate"));
        l1StatsHistogram.record(evictions, Tags.create().addTag(STAT_TYPE_TAG, "evictions"));
        l1StatsHistogram.record(tableCount, Tags.create().addTag(STAT_TYPE_TAG, "table_count"));
    }

    /**
     * Records a KMS call: count + latency, tagged by op ({@code generate_data_key} / {@code decrypt}) and
     * result ({@code ok} / {@code transient} / {@code error}; transient = throttle/rate-limit/network per
     * {@code KeyCacheException.classify}). KMS throttling is a known latency cause; the generic
     * {@code crypto.error.total{kms_key_error}} counter has no op split and no latency. This histogram carries
     * the latency dimension; the failure <em>count</em> is folded into {@code crypto.error.total} (critical
     * failures already record {@code KMS_KEY_ERROR}), so there is no separate KMS-failure counter.
     */
    public void recordKmsCall(String op, String result, long latencyMs) {
        if (kmsCallHistogram == null)
            return;
        kmsCallHistogram.record(latencyMs, Tags.create().addTag(OP_TAG, op).addTag(RESULT_TAG, result));
    }

    /**
     * Increments the low-latency throttle-engaged counter on a clear-&gt;engaged transition, so an alarm can
     * fire immediately rather than waiting for the periodic telemetry tick.
     *
     * @param throttleArm which check engaged ("direct", "os", "direct+os")
     */
    public void recordThrottleEngaged(String throttleArm) {
        if (throttleEngagedCounter == null)
            return;
        throttleEngagedCounter
            .add(1.0, Tags.create().addTag(THROTTLE_ARM_TAG, throttleArm == null || throttleArm.isEmpty() ? "none" : throttleArm));
    }

    /**
     * Increments the degraded-read counter: a block served from a transient, uncached heap buffer because the
     * pool was exhausted/throttled. A non-zero rate is the saturation signal during an incident
     * (the node is shedding cache rather than failing, but is no longer healthy).
     */
    public void recordDegradedRead() {
        if (degradedReadCounter == null)
            return;
        degradedReadCounter.add(1.0);
    }

    /**
     * Records L2 (Caffeine block) cache statistics as separate time series. All counts and the derived
     * rate/latency are PER-INTERVAL deltas (this telemetry tick minus the last), NOT lifetime cumulative
     * totals — so the dashboard is a plain {@code avg(value)} with no {@code derivative()} (which mis-handles
     * JVM-restart counter resets and cannot compute a per-interval hit-rate across separate series). The one
     * exception is {@code size}, an instantaneous gauge. See {@code CaffeineBlockCache#recordStats}.
     *
     * @param size cache size (instantaneous gauge, NOT a delta)
     * @param hits hits in this interval
     * @param misses misses in this interval
     * @param hitRate hit rate percentage over this interval (0-100)
     * @param loads loads in this interval
     * @param evictions evictions in this interval
     * @param avgLoadTimeMs average load time over this interval, in milliseconds
     */
    public void recordCacheStats(long size, long hits, long misses, double hitRate, long loads, long evictions, double avgLoadTimeMs) {
        if (cacheStatsHistogram == null)
            return;

        cacheStatsHistogram.record(size, Tags.create().addTag(STAT_TYPE_TAG, "size"));
        cacheStatsHistogram.record(hits, Tags.create().addTag(STAT_TYPE_TAG, "hits"));
        cacheStatsHistogram.record(misses, Tags.create().addTag(STAT_TYPE_TAG, "misses"));
        cacheStatsHistogram.record(hitRate, Tags.create().addTag(STAT_TYPE_TAG, "hit_rate"));
        cacheStatsHistogram.record(loads, Tags.create().addTag(STAT_TYPE_TAG, "loads"));
        cacheStatsHistogram.record(evictions, Tags.create().addTag(STAT_TYPE_TAG, "evictions"));
        cacheStatsHistogram.record(avgLoadTimeMs, Tags.create().addTag(STAT_TYPE_TAG, "avg_load_time"));
    }

    /**
     * Records error count by error type.
     * @param errorType the type of error
     */
    public void recordError(@NonNull ErrorType errorType) {
        if (errorCounter != null) {
            errorCounter.add(1.0, Tags.create().addTag(ERROR_TYPE_TAG, errorType.getValue()));
        }
    }

    /**
     * Records error count by error type at index level.
     * @param errorType the type of error
     * @param indexName the index name
     */
    public void recordError(@NonNull ErrorType errorType, @NonNull String indexName) {
        if (errorCounter != null) {
            errorCounter.add(1.0, Tags.create().addTag(ERROR_TYPE_TAG, errorType.getValue()).addTag(INDEX_NAME, indexName));
        }
    }

    // Private helper methods
    private Counter createCounter(String name, String description, String unit) {
        return metricsRegistry != null ? metricsRegistry.createCounter(name, description, unit) : null;
    }

    private Histogram createHistogram(String name, String description, String unit) {
        return metricsRegistry != null ? metricsRegistry.createHistogram(name, description, unit) : null;
    }

}
