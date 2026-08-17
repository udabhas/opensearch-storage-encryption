/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.nio.file.Path;

import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.RandomAccessInput;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTable;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTableRegistry;
import org.opensearch.index.store.bufferpoolfs.StaticConfigs;

/**
 * RandomAccessInput backed by block cache with NIO disk fallback.
 * Each read checks L1 (RadixBlockTable, lock-free) first, then L2 (Caffeine), then disk.
 *
 * <p>Extracted from {@link CryptoBufferedIndexInput} (previously a private nested class) so its
 * read paths can be unit-tested in isolation. Behaviour is unchanged by the extraction.
 */
final class CachedRandomAccessInput implements RandomAccessInput {
    private static final ValueLayout.OfByte LAYOUT_BYTE = ValueLayout.JAVA_BYTE;
    private static final ValueLayout.OfShort LE_SHORT = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfInt LE_INT = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfLong LE_LONG = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    private final Path path;
    private final long base;
    private final long len;
    private final long mask;
    private final BlockCache<RefCountedByteBuffer> cache;
    private final RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixTable;
    private final RadixBlockTableRegistry registry;
    private final IndexInput diskFallback;

    CachedRandomAccessInput(
        Path path,
        long base,
        long len,
        long mask,
        BlockCache<RefCountedByteBuffer> cache,
        RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixTable,
        RadixBlockTableRegistry registry,
        IndexInput diskFallback
    ) {
        this.path = path;
        this.base = base;
        this.len = len;
        this.mask = mask;
        this.cache = cache;
        this.radixTable = radixTable;
        this.registry = registry;
        this.diskFallback = diskFallback;
    }

    @Override
    public long length() {
        return len;
    }

    @Override
    public byte readByte(long pos) throws IOException {
        try {
            MemorySegment seg = pinBlock(pos, Byte.BYTES);
            if (seg == null)
                return readFallbackByte(pos);
            long offsetInBlock = (base + pos) & mask;
            return seg.get(LAYOUT_BYTE, offsetInBlock);
        } catch (IOException e) {
            return readFallbackByte(pos);
        }
    }

    @Override
    public short readShort(long pos) throws IOException {
        try {
            MemorySegment seg = pinBlock(pos, Short.BYTES);
            if (seg == null)
                return readFallbackShort(pos);
            long offsetInBlock = (base + pos) & mask;
            if (offsetInBlock + Short.BYTES > StaticConfigs.CACHE_BLOCK_SIZE) {
                return readFallbackShort(pos);
            }
            return seg.get(LE_SHORT, offsetInBlock);
        } catch (IOException e) {
            return readFallbackShort(pos);
        }
    }

    @Override
    public int readInt(long pos) throws IOException {
        try {
            MemorySegment seg = pinBlock(pos, Integer.BYTES);
            if (seg == null)
                return readFallbackInt(pos);
            long offsetInBlock = (base + pos) & mask;
            if (offsetInBlock + Integer.BYTES > StaticConfigs.CACHE_BLOCK_SIZE) {
                return readFallbackInt(pos);
            }
            return seg.get(LE_INT, offsetInBlock);
        } catch (IOException e) {
            return readFallbackInt(pos);
        }
    }

    @Override
    public long readLong(long pos) throws IOException {
        try {
            MemorySegment seg = pinBlock(pos, Long.BYTES);
            if (seg == null)
                return readFallbackLong(pos);
            long offsetInBlock = (base + pos) & mask;
            if (offsetInBlock + Long.BYTES > StaticConfigs.CACHE_BLOCK_SIZE) {
                return readFallbackLong(pos);
            }
            return seg.get(LE_LONG, offsetInBlock);
        } catch (IOException e) {
            return readFallbackLong(pos);
        }
    }

    /**
     * Resolve the block containing the given position from L1 → L2 cache.
     * Returns the MemorySegment or null if unavailable.
     */
    private MemorySegment pinBlock(long pos, int readSize) throws IOException {
        long absPos = base + pos;
        long blockOffset = absPos & ~mask;
        long blockId = blockOffset >>> StaticConfigs.CACHE_BLOCK_SIZE_POWER;

        // L1 lookup (lock-free, two array reads)
        if (radixTable != null) {
            BlockCacheValue<RefCountedByteBuffer> entry = radixTable.get(blockId);
            if (entry != null) {
                if (registry != null)
                    registry.recordHit();
                return entry.value().segment();
            }
            if (registry != null)
                registry.recordMiss();
        }

        // L2 lookup
        FileBlockCacheKey key = new FileBlockCacheKey(path, blockOffset);
        BlockCacheValue<RefCountedByteBuffer> v = cache.get(key);
        if (v != null) {
            // Publish to L1
            if (radixTable != null && !v.isTransient()) {
                radixTable.put(blockId, v);
            }
            return v.value().segment();
        }

        // L2 miss — try to load
        BlockCacheValue<RefCountedByteBuffer> loaded = cache.getOrLoad(key);
        if (loaded != null) {
            if (radixTable != null && !loaded.isTransient()) {
                radixTable.put(blockId, loaded);
            }
            return loaded.value().segment();
        }

        return null; // caller falls back to NIO
    }

    // ---- Disk fallback methods (synchronized to share the IndexInput safely) ----

    private byte readFallbackByte(long pos) throws IOException {
        synchronized (diskFallback) {
            diskFallback.seek(pos);
            return diskFallback.readByte();
        }
    }

    private short readFallbackShort(long pos) throws IOException {
        synchronized (diskFallback) {
            diskFallback.seek(pos);
            return diskFallback.readShort();
        }
    }

    private int readFallbackInt(long pos) throws IOException {
        synchronized (diskFallback) {
            diskFallback.seek(pos);
            return diskFallback.readInt();
        }
    }

    private long readFallbackLong(long pos) throws IOException {
        synchronized (diskFallback) {
            diskFallback.seek(pos);
            return diskFallback.readLong();
        }
    }
}
