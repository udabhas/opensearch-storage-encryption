/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE_POWER;

import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCacheValue;

/**
 * Registry that manages per-file {@link RadixBlockTable} instances and routes
 * L2 eviction notifications to the correct table.
 *
 * <h2>Purpose</h2>
 * Each file gets its own RadixBlockTable for L1 caching. When the shared Caffeine
 * L2 cache evicts a block, the eviction listener needs to find the correct file's
 * RadixBlockTable to call {@code remove(blockId)} on. This registry provides that
 * file-path-to-table mapping.
 *
 * <h2>Reference counting</h2>
 * Multiple IndexInput instances (clones, slices) may share the same RadixBlockTable
 * for a given file. The registry tracks a reference count per entry:
 * <ul>
 *   <li>{@link #acquire(Path)} increments the ref count (or creates a new entry)</li>
 *   <li>{@link #release(Path)} decrements it; when it reaches 0, the entry is removed</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * All operations are thread-safe via {@link ConcurrentHashMap#compute}.
 */
public class RadixBlockTableRegistry {

    private static class RegistryEntry {
        final RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> table;
        final AtomicInteger refCount;

        RegistryEntry(RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> table) {
            this.table = table;
            this.refCount = new AtomicInteger(1);
        }
    }

    private final ConcurrentHashMap<Path, RegistryEntry> tables = new ConcurrentHashMap<>();
    private final LongAdder l1Hits = new LongAdder();
    private final LongAdder l1Misses = new LongAdder();
    private final LongAdder l1Evictions = new LongAdder();

    // Previous cumulative snapshots, so recordStats() publishes the PER-INTERVAL delta (this tick minus last
    // tick) rather than lifetime cumulative counters — same rationale as CaffeineBlockCache#previousStats:
    // avoids the dashboard-side derivative() (JVM-restart reset spikes, no cross-series per-interval hit-rate).
    // These raw LongAdders are not Caffeine CacheStats, so the delta is computed by hand. Only read/written on
    // the single-threaded telemetry tick, so no synchronization is needed.
    private long prevL1Hits = 0L;
    private long prevL1Misses = 0L;
    private long prevL1Evictions = 0L;

    /**
     * Acquires a RadixBlockTable for the given file path. If a table already exists
     * for this path, increments the reference count and returns it. Otherwise creates
     * a new table.
     *
     * @param path the normalized absolute file path
     * @return the RadixBlockTable for this file
     */
    public RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> acquire(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        return tables.compute(normalized, (k, existing) -> {
            if (existing != null) {
                existing.refCount.incrementAndGet();
                return existing;
            }
            return new RegistryEntry(new RadixBlockTable<>());
        }).table;
    }

    /**
     * Releases a reference to the RadixBlockTable for the given file path.
     * When the reference count reaches 0, the table is cleared and removed
     * from the registry.
     *
     * @param path the normalized absolute file path
     */
    public void release(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        tables.computeIfPresent(normalized, (k, entry) -> {
            if (entry.refCount.decrementAndGet() <= 0) {
                entry.table.clear();
                return null; // remove from map
            }
            return entry;
        });
    }

    /**
     * Called when the L2 Caffeine cache evicts a block. Routes the eviction
     * to the correct file's RadixBlockTable, clearing the L1 entry so that
     * future reads see a clean miss rather than a stale pointer.
     *
     * @param path the file path of the evicted block
     * @param blockOffset the block-aligned byte offset of the evicted block
     */
    public void onEviction(Path path, long blockOffset) {
        // path is already normalized by FileBlockCacheKey
        RegistryEntry entry = tables.get(path);
        if (entry != null) {
            long blockId = blockOffset >>> CACHE_BLOCK_SIZE_POWER;
            entry.table.remove(blockId);
            l1Evictions.increment();
        }
    }

    /**
     * Clears every L1 block entry for a single file's table directly, without waiting for L2-eviction
     * callbacks and without touching the table's reference count (the table object is preserved so any
     * open IndexInput/slice keeps using it; it just starts empty again).
     *
     * <p>Called from {@code deleteFile}/{@code rename} so L1 coherence on a delete-then-recreate at the same
     * path does NOT depend on the L2 removal listener firing. The reader-side {@code publishToL1} re-check
     * narrows but cannot fully close the publish-after-evict window (a reader can re-install an entry after
     * the per-block {@code onEviction} ran); clearing the whole file's table here removes that dependency:
     * after the unlink, the next reader of the recreated path sees a clean L1 miss and reloads from the new
     * inode rather than being served the old inode's bytes (silent under unauthenticated AES-CTR).
     *
     * @param path the file path whose L1 table should be emptied (normalized internally)
     */
    public void clearFile(Path path) {
        Path normalized = path.toAbsolutePath().normalize();
        RegistryEntry entry = tables.get(normalized);
        if (entry != null) {
            entry.table.clear();
        }
    }

    /**
     * Clears all block entries from every registered RadixBlockTable,
     * but preserves the registry entries so that future L2 eviction
     * callbacks still route correctly to active tables.
     * Used by the flush API.
     */
    public void clearContents() {
        tables.forEach((path, entry) -> entry.table.clear());
    }

    /**
     * Clears all entries from the registry. Used during shutdown.
     */
    public void clear() {
        tables.forEach((path, entry) -> entry.table.clear());
        tables.clear();
    }

    public void recordHit() {
        l1Hits.increment();
    }

    public void recordMiss() {
        l1Misses.increment();
    }

    public int getTableCount() {
        return tables.size();
    }

    public long getL1Hits() {
        return l1Hits.sum();
    }

    public long getL1Misses() {
        return l1Misses.sum();
    }

    public long getL1Evictions() {
        return l1Evictions.sum();
    }

    /**
     * Human-readable single-line summary of L1 (RadixBlockTable) cache effectiveness for the 10s
     * log-line telemetry path in {@code BufferPoolDirectory.logCacheAndPoolStats}. Counters are
     * lifetime cumulative sums, matching the sibling {@code CaffeineBlockCache.cacheStats} and
     * {@code MemorySegmentPool.poolStats} log-line format; the per-interval delta view is emitted
     * separately via {@link #recordStats()} to the OTLP metrics path.
     */
    public String l1Stats() {
        long hits = l1Hits.sum();
        long misses = l1Misses.sum();
        long total = hits + misses;
        double hitRate = total > 0 ? (double) hits / total * 100.0 : 0.0;
        return String
            .format(
                "L1[tables=%d, hits=%d, misses=%d, hitRate=%.2f%%, evictions=%d]",
                tables.size(),
                hits,
                misses,
                hitRate,
                l1Evictions.sum()
            );
    }

    /**
     * Emit L1 (RadixBlockTable) cache-effectiveness metrics on the telemetry tick. These counters are
     * incremented on every read (hit/miss) and every L2-eviction callback but are not otherwise
     * surfaced; a dropping L1 hit rate is the leading indicator of the cold-segment decrypt latency the
     * plugin fights, and is otherwise not observable. Best-effort: never let metrics break the pool.
     */
    public void recordStats() {
        // Publish the PER-INTERVAL delta (since the last tick), not lifetime cumulative sums — see the
        // prevL1* fields. hitRate is computed over just this interval's hits+misses, so a degrading L1 is
        // visible immediately and the dashboard needs no derivative(). tableCount is an instantaneous gauge
        // (current number of open files), published as-is.
        long hits = l1Hits.sum();
        long misses = l1Misses.sum();
        long evictions = l1Evictions.sum();

        long deltaHits = hits - prevL1Hits;
        long deltaMisses = misses - prevL1Misses;
        long deltaEvictions = evictions - prevL1Evictions;
        prevL1Hits = hits;
        prevL1Misses = misses;
        prevL1Evictions = evictions;

        long deltaTotal = deltaHits + deltaMisses;
        double hitRate = deltaTotal > 0 ? (double) deltaHits / deltaTotal * 100.0 : 0.0;
        // Bare call — invoked from the pool telemetry thread (created only after the metrics singleton is
        // initialized at node startup), and TelemetryThread.publishStats already wraps this in try/catch.
        org.opensearch.index.store.metrics.CryptoMetricsService
            .getInstance()
            .recordL1Stats(deltaHits, deltaMisses, hitRate, deltaEvictions, tables.size());
    }
}
