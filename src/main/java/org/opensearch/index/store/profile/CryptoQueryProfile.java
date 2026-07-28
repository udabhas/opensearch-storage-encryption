/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import org.opensearch.search.profile.AbstractProfileBreakdown;
import org.opensearch.search.profile.ProfileBreakdownHolder;
import org.opensearch.search.profile.ProfileMetric;
import org.opensearch.search.profile.Timer;

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

    private Timer timer(String name) {
        ProfileMetric m = breakdown.getMetric(name);
        return (m instanceof Timer t) ? t : null;
    }

    private CryptoCounterMetric counter(String name) {
        ProfileMetric m = breakdown.getMetric(name);
        return (m instanceof CryptoCounterMetric c) ? c : null;
    }

    // ---- Timers ----
    public Timer decryptTimer() {
        return timer(CryptoProfileNames.DECRYPT);
    }

    public Timer directIoReadTimer() {
        return timer(CryptoProfileNames.DIRECTIO_READ);
    }

    public Timer footerHkdfTimer() {
        return timer(CryptoProfileNames.FOOTER_HKDF);
    }

    public Timer poolWaitTimer() {
        return timer(CryptoProfileNames.POOL_WAIT);
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
