/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import org.opensearch.search.profile.AbstractProfileBreakdown;
import org.opensearch.search.profile.ProfileBreakdownHolder;
import org.opensearch.search.profile.ProfileMetric;

/**
 * Per-query-node accessor for the storage-encryption profiler metrics.
 *
 * <p>The plugin registers its metrics via {@code SearchPlugin.getQueryProfileMetricsProvider()}; the
 * core creates one metric-set per (query-node, leaf) breakdown. During leaf scoring,
 * {@link ProfileBreakdownHolder} exposes that breakdown on the search thread. Deep read-path code
 * calls {@link #current()} (null when not profiling) and records into the timers/counters by name.
 *
 * <p>Extendable: add an accessor here per new metric and one record call at the new cost center.
 */
public final class CryptoQueryProfile {

    private final AbstractProfileBreakdown breakdown;

    private CryptoQueryProfile(AbstractProfileBreakdown breakdown) {
        this.breakdown = breakdown;
    }

    /** @return a handle to the current leaf's crypto profile, or {@code null} when not profiling. */
    public static CryptoQueryProfile current() {
        AbstractProfileBreakdown b = ProfileBreakdownHolder.get();
        return b == null ? null : new CryptoQueryProfile(b);
    }

    private CryptoNanosMetric nanos(String name) {
        ProfileMetric m = breakdown.getMetric(name);
        return (m instanceof CryptoNanosMetric n) ? n : null;
    }

    private CryptoCounterMetric counter(String name) {
        ProfileMetric m = breakdown.getMetric(name);
        return (m instanceof CryptoCounterMetric c) ? c : null;
    }

    private CryptoHistogramMetric histogram(String name) {
        ProfileMetric m = breakdown.getMetric(name);
        return (m instanceof CryptoHistogramMetric h) ? h : null;
    }

    // ---- Nanos totals (phases with no histogram; not Timers, so not summed into time_in_nanos) ----
    public CryptoNanosMetric footerHkdfTimer() {
        return nanos(CryptoProfileNames.FOOTER_HKDF);
    }

    public CryptoNanosMetric poolWaitTimer() {
        return nanos(CryptoProfileNames.POOL_WAIT);
    }

    public CryptoNanosMetric l1LookupTimer() {
        return nanos(CryptoProfileNames.L1_LOOKUP);
    }

    public CryptoNanosMetric l2LookupTimer() {
        return nanos(CryptoProfileNames.L2_LOOKUP);
    }

    // ---- Histograms (per-sample distributions) ----
    /** Record one total-{@code load()} latency sample (ns) → crypto_load_dist p50/p90/p99. */
    public void recordLoadLatency(long ns) {
        CryptoHistogramMetric h = histogram(CryptoProfileNames.LOAD_DIST);
        if (h != null)
            h.record(ns);
    }

    public void recordIoLatency(long ns) {
        CryptoHistogramMetric h = histogram(CryptoProfileNames.IO_LATENCY_DIST);
        if (h != null)
            h.record(ns);
    }

    public void recordReadSize(long bytes) {
        CryptoHistogramMetric h = histogram(CryptoProfileNames.READ_SIZE_DIST);
        if (h != null)
            h.record(bytes);
    }

    public void recordDecryptLatency(long ns) {
        CryptoHistogramMetric h = histogram(CryptoProfileNames.DECRYPT_DIST);
        if (h != null)
            h.record(ns);
    }

    // ---- Counters ----
    public void incL1Hits() {
        CryptoCounterMetric c = counter(CryptoProfileNames.L1_HITS);
        if (c != null)
            c.increment();
    }

    public void incL1Misses() {
        CryptoCounterMetric c = counter(CryptoProfileNames.L1_MISSES);
        if (c != null)
            c.increment();
    }

    public void incL2Hits() {
        CryptoCounterMetric c = counter(CryptoProfileNames.L2_HITS);
        if (c != null)
            c.increment();
    }

    public void incL2Misses() {
        CryptoCounterMetric c = counter(CryptoProfileNames.L2_MISSES);
        if (c != null)
            c.increment();
    }

    public void incBlocksDecrypted() {
        CryptoCounterMetric c = counter(CryptoProfileNames.BLOCKS_DECRYPTED);
        if (c != null)
            c.increment();
    }

    public void addBytesRead(long n) {
        CryptoCounterMetric c = counter(CryptoProfileNames.BYTES_READ);
        if (c != null)
            c.add(n);
    }

    public void incDegradedReads() {
        CryptoCounterMetric c = counter(CryptoProfileNames.DEGRADED_READS);
        if (c != null)
            c.increment();
    }
}
