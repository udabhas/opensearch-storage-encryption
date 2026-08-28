/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import org.opensearch.index.store.PanamaNativeAccess;

/**
 * Static configuration constants for the encrypted storage buffer pool and Direct I/O operations.
 *
 * <p>These configurations are intentionally static and immutable, not dynamic settings.
 * They are determined at JVM startup based on system properties and cannot be changed
 * at runtime. This design ensures:
 * <ul>
 *   <li>Consistent behavior across all indices using encrypted storage</li>
 *   <li>Memory allocations and buffer sizes remain stable throughout the JVM lifecycle</li>
 *   <li>Direct I/O alignment requirements are satisfied based on system page size</li>
 *   <li>No runtime overhead from dynamic configuration lookups</li>
 * </ul>
 *
 * <p>If you need to change these values, they must be set via JVM properties or code changes,
 * and require a node restart to take effect.
 */
public class StaticConfigs {

    // Prevent instantiation
    private StaticConfigs() {
        throw new AssertionError("Utility class - do not instantiate");
    }

    /** 
     * Alignment requirement for Direct I/O operations in bytes.
     * Must be at least 512 bytes or the system page size, whichever is larger.
     */
    public static final int DIRECT_IO_ALIGNMENT = Math.max(512, getPageSizeSafe());

    /** 
     * Power of 2 for Direct I/O write buffer size (2^18 = 256KB).
     */
    public static final int DIRECT_IO_WRITE_BUFFER_SIZE_POWER = 18;

    /**
     * System property to override the cache block size, expressed as a power of 2 (the log2 of the
     * block size in bytes). Default {@code 13} = 8KB blocks. Example: {@code -Dopensearch.crypto.cache_block_size_power=15}
     * gives 32KB blocks.
     *
     * <p>Read once at class initialization (see {@link #resolveCacheBlockSizePower()}); changing it
     * requires a node restart, consistent with the static-config contract of this class. The whole
     * read/write/pool/cache stack derives its block geometry from {@link #CACHE_BLOCK_SIZE_POWER}, so
     * this single knob resizes every block uniformly. Kept {@code static final} so the JIT still
     * constant-folds the bit-shifts on the hot path.
     */
    public static final String CACHE_BLOCK_SIZE_POWER_PROPERTY = "opensearch.crypto.cache_block_size_power";

    /**
     * Default cache block size power (2^16 = 64KB). Chosen from the big5 block-size sweep: 64KB gave
     * ~2.7x faster cold search vs 8KB (and eliminated the heavy-agg timeouts) while keeping warm/hot at
     * ~mmap parity — the best cold-win-with-least-warm-regression point. 128KB improves the heavy cold
     * tail slightly more but adds no hot benefit and larger small-query over-read. Override via
     * {@link #CACHE_BLOCK_SIZE_POWER_PROPERTY}.
     */
    public static final int DEFAULT_CACHE_BLOCK_SIZE_POWER = 16;

    /**
     * Minimum allowed block-size power. Below 2^9 (512B) the block can be smaller than the Direct I/O
     * alignment, which would break O_DIRECT block reads.
     */
    private static final int MIN_CACHE_BLOCK_SIZE_POWER = 9;

    /**
     * Maximum allowed block-size power. 2^24 = 16MB — well above any sensible block; a guard against
     * a fat-fingered value that would exhaust the pool with a single block.
     */
    private static final int MAX_CACHE_BLOCK_SIZE_POWER = 24;

    /**
     * Power of 2 for cache block size. Defaults to {@value #DEFAULT_CACHE_BLOCK_SIZE_POWER} (2^16 = 64KB),
     * overridable via {@link #CACHE_BLOCK_SIZE_POWER_PROPERTY}.
     */
    public static final int CACHE_BLOCK_SIZE_POWER = resolveCacheBlockSizePower();

    /**
     * Size of each cache block in bytes (default 8KB; see {@link #CACHE_BLOCK_SIZE_POWER}).
     */
    public static final int CACHE_BLOCK_SIZE = 1 << CACHE_BLOCK_SIZE_POWER;

    /**
     * Bit mask for cache block alignment (block_size - 1).
     */
    public static final long CACHE_BLOCK_MASK = CACHE_BLOCK_SIZE - 1;

    /**
     * Resolve the cache block-size power from the system property, clamped to a safe range and
     * validated against the Direct I/O alignment. Falls back to {@link #DEFAULT_CACHE_BLOCK_SIZE_POWER}
     * on any parse error or out-of-range / mis-aligned value. Runs once at class init.
     */
    private static int resolveCacheBlockSizePower() {
        int power = DEFAULT_CACHE_BLOCK_SIZE_POWER;
        String raw = System.getProperty(CACHE_BLOCK_SIZE_POWER_PROPERTY);
        if (raw != null && !raw.isBlank()) {
            try {
                int parsed = Integer.parseInt(raw.trim());
                if (parsed < MIN_CACHE_BLOCK_SIZE_POWER || parsed > MAX_CACHE_BLOCK_SIZE_POWER) {
                    throw new IllegalArgumentException(
                        "must be in [" + MIN_CACHE_BLOCK_SIZE_POWER + ", " + MAX_CACHE_BLOCK_SIZE_POWER + "]"
                    );
                }
                power = parsed;
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("Invalid " + CACHE_BLOCK_SIZE_POWER_PROPERTY + "=[" + raw + "]: " + e.getMessage());
            }
        }
        // O_DIRECT requires the block to be a whole multiple of the device alignment. Since both are
        // powers of two, this holds iff the block is >= the alignment.
        if ((1 << power) < DIRECT_IO_ALIGNMENT) {
            throw new IllegalArgumentException(
                CACHE_BLOCK_SIZE_POWER_PROPERTY
                    + "="
                    + power
                    + " yields block "
                    + (1 << power)
                    + "B, smaller than Direct I/O alignment "
                    + DIRECT_IO_ALIGNMENT
                    + "B"
            );
        }
        return power;
    }

    /**
     * Feature flag for read-path CPU optimizations. Gates:
     * <ul>
     *   <li>{@link org.opensearch.index.store.block.RefCountedByteBuffer} segment construction
     *       (global-arena reinterpret vs buffer-scoped {@code MemorySegment.ofBuffer}).</li>
     *   <li>{@code CachedMemorySegmentIndexInput} slice path-normalize skip.</li>
     * </ul>
     *
     * <p>Defaults to {@code false}: the optimization is opt-in and is wired (if at all)
     * once at plugin startup from a cluster setting. The buffer-scoped {@code MemorySegment.ofBuffer}
     * path is the safe default and matches prior behavior.
     */
    private static volatile boolean memorySegmentGlobalArenaAndNormalizePathOptimEnabled = false;

    /**
     * Returns whether read-path CPU optimizations are enabled.
     * See {@link #memorySegmentGlobalArenaAndNormalizePathOptimEnabled} field docs.
     */
    public static boolean memorySegmentGlobalArenaAndNormalizePathOptimEnabled() {
        return memorySegmentGlobalArenaAndNormalizePathOptimEnabled;
    }

    /**
     * Sets the read-path CPU optimization feature flag. Intended to be called once at plugin
     * startup (e.g. from {@code CryptoDirectoryPlugin.createComponents()}).
     */
    public static void setMemorySegmentGlobalArenaAndNormalizePathOptimEnabled(boolean value) {
        memorySegmentGlobalArenaAndNormalizePathOptimEnabled = value;
    }

    /**
     * Feature flag for the block-cache bypass path on {@code CachedMemorySegmentIndexInput}: when
     * enabled, inputs are opened with {@code skipCache}, so every block is read from disk via
     * DirectIO and decrypted without consulting or populating L1/L2.
     *
     * <p>Defaults to {@code false} — the cached path is the safe default and matches prior behavior.
     * This flag currently applies to ALL inputs opened through the DEFAULT (block-cache) route, so it
     * is an experiment/measurement switch, not a production setting: the intended production trigger
     * is a per-input decision made where the input is created or cloned, not a global toggle.
     */
    /**
     * System property setting the INITIAL value of the bypass flag, so the experiment can be run without
     * editing a shipped default. {@link #setBlockCacheBypassEnabled} still overrides at runtime.
     */
    public static final String BLOCK_CACHE_BYPASS_PROPERTY = "opensearch.store.block_cache_bypass";

    private static volatile boolean blockCacheBypassEnabled = Boolean
        .parseBoolean(System.getProperty(BLOCK_CACHE_BYPASS_PROPERTY, "false"));

    /**
     * Returns whether inputs should be opened with the block-cache bypass.
     * See {@link #blockCacheBypassEnabled} field docs.
     */
    public static boolean blockCacheBypassEnabled() {
        return blockCacheBypassEnabled;
    }

    /**
     * Sets the block-cache bypass feature flag. Intended to be called once at plugin startup.
     */
    public static void setBlockCacheBypassEnabled(boolean value) {
        blockCacheBypassEnabled = value;
    }

    /**
     * System property gating the SNAPSHOT-only bufferpool bypass (see
     * {@code BufferPoolDirectory#enableSkipBufferpool}). Default ON.
     *
     * <p>Two purposes, and both are load-bearing. It is the kill switch if the routing turns out to hurt a
     * workload we have not measured, and it is the only way to run a controlled A/B of snapshot-only routing:
     * {@link #BLOCK_CACHE_BYPASS_PROPERTY} bypasses EVERY reader including search, so it cannot isolate the
     * snapshot arm.
     */
    public static final String SNAPSHOT_BYPASS_PROPERTY = "opensearch.store.snapshot_bufferpool_bypass";

    private static volatile boolean snapshotBypassEnabled = Boolean.parseBoolean(System.getProperty(SNAPSHOT_BYPASS_PROPERTY, "true"));

    /** Returns whether snapshot upload reads bypass the bufferpool. */
    public static boolean snapshotBypassEnabled() {
        return snapshotBypassEnabled;
    }

    /** Sets the snapshot-bypass flag. */
    public static void setSnapshotBypassEnabled(boolean value) {
        snapshotBypassEnabled = value;
    }

    /**
     * System property gating the field-data stack-detection experiment. Default OFF.
     *
     * <p>Off by default because the mechanism costs a stack walk on every {@code clone()} / {@code slice()},
     * which is the query hot path (a clone per TermsEnum, a clone per DocsEnum). It exists to MEASURE
     * whether bypassing the cache for field data builds is worth having, before a cheaper signal is built.
     */
    public static final String FIELD_DATA_STACK_DETECT_PROPERTY = "opensearch.store.fielddata_stack_detect";

    private static final boolean FIELD_DATA_STACK_DETECT = Boolean
        .parseBoolean(System.getProperty(FIELD_DATA_STACK_DETECT_PROPERTY, "false"));

    /**
     * Whether derived inputs should stack-walk to detect a field data build and bypass the cache for it.
     * See {@link #FIELD_DATA_STACK_DETECT_PROPERTY}. Experiment only - not a production setting.
     */
    public static boolean fieldDataStackDetectEnabled() {
        return FIELD_DATA_STACK_DETECT;
    }

    private static int getPageSizeSafe() {
        try {
            return PanamaNativeAccess.getPageSize();
        } catch (Throwable e) {
            // Native access not available (class initialization failed, native library not found, etc.)
            // Fall back to common page size
            return 4096;
        }
    }
}
