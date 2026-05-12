/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.locks.LockSupport;

import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;

/**
 * L1 cache in front of the main Caffeine L2 cache.
 *
 * Delegates storage to {@link RadixBlockTable} which provides a per-blockId slot
 * with no hash collisions and lock-free reads (two plain array loads).
 *
 * Each entry stores both the {@link BlockCacheValue} and a generation snapshot.
 * On read we do pin-then-validate: pin the segment, check generation still matches.
 * If the segment was recycled (generation bumped), unpin and treat as L1 miss.
 */
public class BlockSlotTinyCache {

    public static final class CacheHitHolder {
        private boolean wasCacheHit;

        public void reset() {
            wasCacheHit = false;
        }

        public boolean wasCacheHit() {
            return wasCacheHit;
        }

        void setWasCacheHit(boolean hit) {
            this.wasCacheHit = hit;
        }
    }

    static final class L1Entry {
        final BlockCacheValue<RefCountedMemorySegment> value;
        final int generation;

        L1Entry(BlockCacheValue<RefCountedMemorySegment> value, int generation) {
            this.value = value;
            this.generation = generation;
        }
    }

    private final BlockCache<RefCountedMemorySegment> cache;
    private final Path path;
    private final RadixBlockTable<L1Entry> l1Table;

    public BlockSlotTinyCache(BlockCache<RefCountedMemorySegment> cache, Path path, long fileLength) {
        this.cache = cache;
        this.path = path;
        this.l1Table = new RadixBlockTable<>();
    }

    public BlockCacheValue<RefCountedMemorySegment> acquireRefCountedValue(long blockOff) throws IOException {
        return acquireRefCountedValue(blockOff, null);
    }

    public BlockCacheValue<RefCountedMemorySegment> acquireRefCountedValue(long blockOff, CacheHitHolder hitHolder) throws IOException {

        final long blockIdx = blockOff >>> CACHE_BLOCK_SIZE_POWER;

        // L1 lookup — two plain array loads, no fences
        final L1Entry entry = l1Table.get(blockIdx);
        if (entry != null) {
            final BlockCacheValue<RefCountedMemorySegment> v = entry.value;
            if (v.tryPin()) {
                if (v.value().getGeneration() == entry.generation) {
                    if (hitHolder != null)
                        hitHolder.setWasCacheHit(true);
                    return v;
                }
                v.unpin();
            }
            // Stale entry — remove from L1
            l1Table.remove(blockIdx);
        }

        // L1 miss — fall through to L2
        final int maxAttempts = 10;
        final FileBlockCacheKey key = new FileBlockCacheKey(path, blockOff);

        for (int attempts = 0; attempts < maxAttempts; attempts++) {
            // 1) Prefer L2 hit
            BlockCacheValue<RefCountedMemorySegment> v = cache.get(key);
            if (v != null) {
                final int expectedGen = v.value().getGeneration();
                if (v.tryPin()) {
                    if (v.value().getGeneration() == expectedGen) {
                        l1Table.put(blockIdx, new L1Entry(v, expectedGen));
                        if (hitHolder != null)
                            hitHolder.setWasCacheHit(true);
                        return v;
                    }
                    v.unpin();
                }
            }

            // 2) Load path (deduped by caffeine get())
            BlockCacheValue<RefCountedMemorySegment> loaded = cache.getOrLoad(key);
            if (loaded != null) {
                final int expectedGen = loaded.value().getGeneration();
                if (loaded.tryPin()) {
                    if (loaded.value().getGeneration() == expectedGen) {
                        l1Table.put(blockIdx, new L1Entry(loaded, expectedGen));
                        if (hitHolder != null)
                            hitHolder.setWasCacheHit(false);
                        return loaded;
                    }
                    loaded.unpin();
                }
            }

            if (attempts < maxAttempts - 1) {
                LockSupport.parkNanos(50_000L << attempts);
            }
        }

        throw new IOException("Unable to pin memory segment for block offset " + blockOff + " after " + maxAttempts + " attempts");
    }

    public void clear() {
        l1Table.clear();
    }
}
