/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.lang.management.ManagementFactory;
import java.util.Locale;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.Settings;
import org.opensearch.monitor.os.OsProbe;

/**
 * Utility class for calculating memory pool sizes based on node configuration and available memory.
 *
 * <p>Two-config model (GC-managed direct-ByteBuffer pool):
 * <ul>
 *   <li>{@code pool_size_percentage} — fraction of MaxDirectMemorySize for the pool (= cache size, 1:1)</li>
 *   <li>{@code gc_headroom_fraction} — extra headroom beyond pool for GC zombie lag</li>
 * </ul>
 *
 * <pre>
 * pool = maxDirectMemory * pool_size_percentage
 * cache = pool  (1:1)
 * allocation_limit = pool + pool * gc_headroom_fraction
 * </pre>
 *
 * <p>The GC headroom exists because the pool hands out direct {@link java.nio.ByteBuffer}s whose
 * native memory is freed by the GC's {@code Cleaner} rather than synchronously on release. Buffers
 * dropped by readers remain "zombie" allocations until the next GC cycle, so the allocation limit
 * must sit below MaxDirectMemorySize to absorb that lag without hitting {@code OutOfMemoryError}.
 */
public final class PoolSizeCalculator {

    private static final Logger LOGGER = LogManager.getLogger(PoolSizeCalculator.class);

    /** Minimum pool size: 256 MB */
    private static final long MIN_POOL_SIZE_MB = 256;

    /**
     * Percentage of off-heap (MaxDirectMemorySize) to use for the pool (and cache) on machines with
     * {@link #SMALL_MACHINE_THRESHOLD_BYTES} or more total physical memory.
     */
    public static final Setting<Double> NODE_POOL_SIZE_PERCENTAGE_SETTING = Setting
        .doubleSetting("node.store.crypto.pool_size_percentage", 0.7, 0.0, 1.0, Property.NodeScope);

    /**
     * Percentage of off-heap (MaxDirectMemorySize) to use for the pool (and cache) on small machines
     * (total physical memory &lt; {@link #SMALL_MACHINE_THRESHOLD_BYTES}).
     *
     * <p>At 0.70 pool + 0.1429 headroom: pool * 1.1429 = 0.80 of MaxDirect — leaves 20% for other
     * direct-memory consumers (Netty, Lucene, native libs). On a 1200 MB MaxDirect budget:
     * pool = 840 MB, allocation limit = 960 MB.
     */
    public static final Setting<Double> NODE_POOL_SIZE_PERCENTAGE_SMALL_SETTING = Setting
        .doubleSetting("node.store.crypto.pool_size_percentage_small", 0.7, 0.0, 1.0, Property.NodeScope);

    /** Threshold below which the small-machine pool percentage is used (16 GB). */
    static final long SMALL_MACHINE_THRESHOLD_BYTES = 16L * 1024 * 1024 * 1024;

    /**
     * GC headroom as a fraction of pool size. Allocation stalls when
     * buffersInUse exceeds pool * (1 + gc_headroom_fraction).
     *
     * <p>At 0.70 pool + 0.1429 headroom: allocation limit = pool * 1.1429 = 80% of MaxDirect.
     */
    public static final Setting<Double> NODE_GC_HEADROOM_FRACTION_SETTING = Setting
        .doubleSetting("node.store.crypto.gc_headroom_fraction", 0.10, 0.05, 1.0, Property.NodeScope);

    /**
     * Enables the proactive (preventive) cache-shrink monitor: while memory is still healthy but on a
     * filling trajectory (allocation rate &gt; reclamation rate) and utilization is above the threshold,
     * the pool sheds excess cache early so natural GC keeps up and the memory-pressure throttle ideally
     * never engages. <b>Default OFF</b> — enable per-fleet only after observing the
     * {@code crypto.pool.memory.stats} allocation/reclamation-rate gauges. Dynamic (runtime-togglable).
     */
    public static final Setting<Boolean> NODE_PROACTIVE_SHRINK_ENABLED_SETTING = Setting
        .boolSetting("node.store.crypto.proactive_shrink_enabled", false, Property.NodeScope, Property.Dynamic);

    private static final long MB_TO_BYTES = 1024L * 1024L;
    private static final long GB_TO_BYTES = 1024L * 1024L * 1024L;

    /**
     * Calculates the pool size based on MaxDirectMemorySize.
     *
     * <p>pool_size = maxDirectMemory * pool_size_percentage, with a minimum of
     * {@link #MIN_POOL_SIZE_MB} MB applied before validation.
     *
     * <p>Throws {@link IllegalStateException} if {@code -XX:MaxDirectMemorySize}
     * is not explicitly set. Validates that pool + gc_headroom does not exceed
     * MaxDirectMemorySize.
     *
     * @param settings the node settings for configuration
     * @return the calculated pool size in bytes
     * @throws IllegalStateException if MaxDirectMemorySize is not set, or if pool + headroom exceeds it
     */
    public static long calculatePoolSize(Settings settings) {
        double percentage = NODE_POOL_SIZE_PERCENTAGE_SETTING.get(settings);
        double smallPercentage = NODE_POOL_SIZE_PERCENTAGE_SMALL_SETTING.get(settings);
        double gcHeadroomFraction = NODE_GC_HEADROOM_FRACTION_SETTING.get(settings);

        long maxHeap = Runtime.getRuntime().maxMemory();
        long maxDirectMemory = getMaxDirectMemorySize();

        long totalPhysical = 0;
        try {
            totalPhysical = OsProbe.getInstance().getTotalPhysicalMemorySize();
            if (totalPhysical <= 0) {
                LOGGER.warn("Could not detect valid total physical memory: {}", totalPhysical);
                totalPhysical = 0;
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to detect total physical memory; skipping off-heap comparison", e);
        }

        // Small machines (< 16 GB total) use a smaller pool percentage to leave room
        // for other direct-memory consumers.
        double effectivePercentage = selectPercentage(totalPhysical, percentage, smallPercentage);

        return computeAndValidatePoolSize(maxDirectMemory, totalPhysical, maxHeap, effectivePercentage, gcHeadroomFraction);
    }

    /**
     * Returns the configured GC headroom fraction (used by the pool to compute its allocation limit).
     *
     * @param settings the node settings for configuration
     * @return the GC headroom fraction
     */
    public static double getGcHeadroomFraction(Settings settings) {
        return NODE_GC_HEADROOM_FRACTION_SETTING.get(settings);
    }

    /**
     * Selects the pool-size percentage based on total physical memory.
     * Returns {@code smallPercentage} if {@code totalPhysical} is in
     * {@code (0, SMALL_MACHINE_THRESHOLD_BYTES)}; otherwise returns {@code percentage}.
     * At exactly {@link #SMALL_MACHINE_THRESHOLD_BYTES} the normal percentage is used.
     */
    static double selectPercentage(long totalPhysical, double percentage, double smallPercentage) {
        if (totalPhysical > 0 && totalPhysical < SMALL_MACHINE_THRESHOLD_BYTES) {
            return smallPercentage;
        }
        return percentage;
    }

    /**
     * Performs the sizing math and validation. Package-private for unit testing.
     *
     * @throws IllegalStateException if {@code maxDirectMemory <= 0}, or if
     *   pool + gc headroom would exceed {@code maxDirectMemory}.
     */
    static long computeAndValidatePoolSize(
        long maxDirectMemory,
        long totalPhysical,
        long maxHeap,
        double percentage,
        double gcHeadroomFraction
    ) {
        if (maxDirectMemory <= 0) {
            throw new IllegalStateException(
                "MaxDirectMemorySize is not explicitly set. It must be configured via -XX:MaxDirectMemorySize for pool sizing."
            );
        }

        long offHeap = totalPhysical > 0 ? Math.max(0, totalPhysical - maxHeap) : 0;
        if (totalPhysical > 0 && maxDirectMemory != offHeap) {
            LOGGER
                .warn(
                    "MaxDirectMemorySize ({} MB) differs from calculated off-heap ({} MB)",
                    maxDirectMemory / MB_TO_BYTES,
                    offHeap / MB_TO_BYTES
                );
        }

        long calculated = (long) (maxDirectMemory * percentage);

        // Apply minimum bound BEFORE validation so the check accounts for the actual final pool size
        long minBytes = MIN_POOL_SIZE_MB * MB_TO_BYTES;
        calculated = Math.max(minBytes, calculated);

        // Validate that pool + gc headroom fits within max direct memory
        long totalRequired = (long) (calculated * (1 + gcHeadroomFraction));
        if (totalRequired > maxDirectMemory) {
            throw new IllegalStateException(
                String
                    .format(
                        Locale.ROOT,
                        "Pool size with GC headroom (%d MB = pool %d MB * %.2f headroom) exceeds max direct memory (%d MB). "
                            + "Reduce pool_size_percentage or gc_headroom_fraction.",
                        totalRequired / MB_TO_BYTES,
                        calculated / MB_TO_BYTES,
                        1 + gcHeadroomFraction,
                        maxDirectMemory / MB_TO_BYTES
                    )
            );
        }

        LOGGER
            .info(
                String
                    .format(
                        Locale.ROOT,
                        "Calculated pool size = %d MB (%.1f GB) [total=%.1f GB, heap=%.1f GB, maxDirectMemory=%.1f GB, offheap=%.1f GB, percentage=%.1f%%]",
                        calculated / MB_TO_BYTES,
                        calculated / (double) GB_TO_BYTES,
                        totalPhysical / (double) GB_TO_BYTES,
                        maxHeap / (double) GB_TO_BYTES,
                        maxDirectMemory / (double) GB_TO_BYTES,
                        offHeap / (double) GB_TO_BYTES,
                        percentage * 100
                    )
            );
        return calculated;
    }

    /**
     * Returns the JVM's MaxDirectMemorySize. Returns 0 if not explicitly set.
     */
    static long getMaxDirectMemorySize() {
        return ManagementFactory
            .getRuntimeMXBean()
            .getInputArguments()
            .stream()
            .filter(arg -> arg.startsWith("-XX:MaxDirectMemorySize="))
            .map(arg -> parseSize(arg.substring("-XX:MaxDirectMemorySize=".length())))
            .reduce((a, b) -> b) // last one wins
            .orElse(0L);
    }

    static long parseSize(String value) {
        value = value.trim().toLowerCase(Locale.ROOT);
        long multiplier = 1;
        if (value.endsWith("k")) {
            multiplier = 1024L;
            value = value.substring(0, value.length() - 1);
        } else if (value.endsWith("m")) {
            multiplier = MB_TO_BYTES;
            value = value.substring(0, value.length() - 1);
        } else if (value.endsWith("g")) {
            multiplier = GB_TO_BYTES;
            value = value.substring(0, value.length() - 1);
        }
        return Long.parseLong(value) * multiplier;
    }

    private PoolSizeCalculator() {}
}
