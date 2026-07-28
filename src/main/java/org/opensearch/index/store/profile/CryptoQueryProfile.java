/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import org.opensearch.search.profile.AbstractProfileBreakdown;
import org.opensearch.search.profile.ProfileBreakdownHolder;
import org.opensearch.search.profile.Timer;

/**
 * Per-query-node accessor for the storage-encryption profiler metrics.
 *
 * <p>The plugin registers its {@link org.opensearch.search.profile.ProfileMetric}s (e.g. a
 * {@code crypto_decrypt} {@link Timer}) via {@code SearchPlugin.getQueryProfileMetricsProvider()};
 * the core creates one metric-set per (query-node, leaf) breakdown. During leaf scoring,
 * {@link ProfileBreakdownHolder} exposes that breakdown on the search thread. Deep read-path code
 * calls {@link #current()} to get a handle (null when not profiling) and records into the timers/
 * counters it needs.
 *
 * <p>This is intentionally thin: it just looks up our metrics by name in the current breakdown.
 * Extendable — add a getter here per new metric and one call at the new cost center.
 */
public final class CryptoQueryProfile {

    private final AbstractProfileBreakdown breakdown;

    private CryptoQueryProfile(AbstractProfileBreakdown breakdown) {
        this.breakdown = breakdown;
    }

    /**
     * @return a handle to the current leaf's crypto profile, or {@code null} when not profiling
     *         (no active breakdown on this thread).
     */
    public static CryptoQueryProfile current() {
        AbstractProfileBreakdown b = ProfileBreakdownHolder.get();
        return b == null ? null : new CryptoQueryProfile(b);
    }

    /** @return the {@code crypto_decrypt} Timer for this node, or {@code null} if not registered. */
    public Timer decryptTimer() {
        var m = breakdown.getMetric(CryptoProfileNames.DECRYPT);
        return (m instanceof Timer t) ? t : null;
    }
}
