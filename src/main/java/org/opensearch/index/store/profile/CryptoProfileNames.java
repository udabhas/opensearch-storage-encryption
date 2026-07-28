/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

import java.util.Arrays;
import java.util.List;

/**
 * Metric key names for the storage-encryption query profiler. Single source of truth so the
 * registration site ({@code CryptoDirectoryPlugin.getQueryProfileMetricsProvider}), the read-path
 * recording sites, and any dashboards share identical keys.
 *
 * <p>To add a new cost center: (1) add a name here (and to {@link #TIMERS} or {@link #COUNTERS}),
 * (2) add an accessor in {@link CryptoQueryProfile}, (3) record into it at the call site. The
 * provider registers every name in {@link #TIMERS}/{@link #COUNTERS} automatically.
 */
public final class CryptoProfileNames {

    private CryptoProfileNames() {}

    // ---- Timers (wall-clock phases; core reports the span across slices) ----
    /** AES-CTR frame-based decrypt time. */
    public static final String DECRYPT = "crypto_decrypt";
    /** Direct-IO disk read time (readWithZeroByteRetry). */
    public static final String DIRECTIO_READ = "crypto_directio_read";
    /** Footer read + HKDF file-key derivation time. */
    public static final String FOOTER_HKDF = "crypto_footer_hkdf";
    /** Time blocked acquiring pool segments (includes stall/throttle waits). */
    public static final String POOL_WAIT = "crypto_pool_wait";

    // ---- Counters (LongAdder; core sums across slices) ----
    public static final String L1_HITS = "crypto_l1_hits";
    public static final String L1_MISSES = "crypto_l1_misses";
    public static final String L2_HITS = "crypto_l2_hits";
    public static final String L2_MISSES = "crypto_l2_misses";
    public static final String BLOCKS_DECRYPTED = "crypto_blocks_decrypted";
    public static final String BYTES_READ = "crypto_bytes_read";
    public static final String DEGRADED_READS = "crypto_degraded_reads";

    /** All timer metric names. */
    public static final List<String> TIMERS = Arrays.asList(DECRYPT, DIRECTIO_READ, FOOTER_HKDF, POOL_WAIT);

    /** All counter metric names. */
    public static final List<String> COUNTERS = Arrays
        .asList(L1_HITS, L1_MISSES, L2_HITS, L2_MISSES, BLOCKS_DECRYPTED, BYTES_READ, DEGRADED_READS);
}
