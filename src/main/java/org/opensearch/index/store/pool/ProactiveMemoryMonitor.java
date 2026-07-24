/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Proactive, trajectory-based cache-shrink monitor.
 *
 * <p>Fires a <em>preventive</em> cache shrink while memory is still healthy, when the pool is on a
 * filling trajectory toward exhaustion and there is clearly excess cache to give back — so the
 * memory-pressure throttle ideally never engages at all. This is the opposite of the reactive path
 * ({@code onThrottleEngagedHook} + {@code System.gc()} hint) which only fires <em>after</em> the
 * throttle floor is breached.
 *
 * <p>Disabled by default. Controlled by the dynamic cluster setting
 * {@code node.store.crypto.proactive_shrink_enabled} (see
 * {@code CryptoDirectoryPlugin}); enable per-fleet only after observing the allocation/reclamation
 * rate gauges in production.
 *
 * <p>Evaluated once per telemetry tick; shrinks the cache by {@code shrinkStepFraction} of the
 * original capacity only when ALL hold:
 * <ol>
 *   <li>enabled,</li>
 *   <li>allocation rate &gt; reclamation rate (the pool is filling — the {@link AllocationRateMeter} signal),</li>
 *   <li>utilization &ge; {@code utilizationThreshold} (default 70% of the allocation limit),</li>
 *   <li>the cache has slack above a conservative floor (never shrink into the working set).</li>
 * </ol>
 * Reclamation is left to natural GC (no {@code System.gc()} hint here) precisely because it fires
 * early, well ahead of the throttle floor.
 *
 * @opensearch.internal
 */
public final class ProactiveMemoryMonitor {

    private static final Logger LOGGER = LogManager.getLogger(ProactiveMemoryMonitor.class);

    /** {@code node.store.crypto.proactive_shrink_enabled} — default OFF. */
    private volatile boolean enabled = false;
    /** Utilization fraction (of the allocation limit) at/above which a proactive shrink may fire. */
    private volatile double utilizationThreshold = 0.70;
    /** Shrink step as a fraction of the cache's coldest entries, per firing. */
    private volatile double shrinkStepFraction = 0.05;
    /** Never shrink the cache below this fraction of its original capacity (working-set safety floor). */
    private volatile double cacheMinFraction = 0.50;

    public void setEnabled(boolean v) {
        this.enabled = v;
        LOGGER.info("Proactive cache-shrink {}", v ? "ENABLED" : "DISABLED");
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setUtilizationThreshold(double v) {
        this.utilizationThreshold = v;
    }

    public void setShrinkStepFraction(double v) {
        this.shrinkStepFraction = v;
    }

    public void setCacheMinFraction(double v) {
        this.cacheMinFraction = v;
    }

    /**
     * Evaluate the trajectory signal and, if warranted, shrink the cache. Called once per telemetry
     * tick from {@link MemorySegmentPool}. All-or-nothing: returns the number of blocks evicted
     * (0 if no action).
     *
     * @param buffersInUse    current allocated segment count
     * @param allocationLimit soft ceiling (max segments + gc headroom)
     * @param allocRateBps    current allocation rate (bytes/sec)
     * @param reclaimRateBps  current reclamation rate (bytes/sec)
     * @param cacheSize       current cache entry count
     * @param originalCacheMax the boot-time cache capacity (blocks)
     * @param shrink          the shrink primitive (evict coldest fraction) — no-op safe
     * @return blocks evicted, or 0
     */
    long evaluateAndMaybeShrink(
        int buffersInUse,
        int allocationLimit,
        long allocRateBps,
        long reclaimRateBps,
        long cacheSize,
        long originalCacheMax,
        java.util.function.DoubleFunction<Long> shrink
    ) {
        if (!enabled) {
            return 0L;
        }
        // Trajectory: only act while the pool is filling (allocation outpaces reclamation).
        boolean filling = allocRateBps > reclaimRateBps;
        // Utilization threshold against the allocation limit (double comparison — exact boundary).
        boolean approachingExhaustion = allocationLimit > 0 && buffersInUse >= allocationLimit * utilizationThreshold;
        // Cache-slack floor: never shrink into the working set.
        boolean hasSlack = originalCacheMax > 0 && cacheSize > (long) (originalCacheMax * cacheMinFraction);

        if (filling && approachingExhaustion && hasSlack) {
            long evicted = shrink.apply(shrinkStepFraction);
            if (evicted > 0) {
                LOGGER
                    .info(
                        "Proactive cache shrink: evicted {} coldest blocks [inUse={}/{} allocRate={}B/s reclaimRate={}B/s cache={}/{}]",
                        evicted,
                        buffersInUse,
                        allocationLimit,
                        allocRateBps,
                        reclaimRateBps,
                        cacheSize,
                        originalCacheMax
                    );
            }
            return evicted;
        }
        return 0L;
    }
}
