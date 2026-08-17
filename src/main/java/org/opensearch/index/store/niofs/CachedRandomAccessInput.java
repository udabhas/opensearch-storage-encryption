/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Reference;
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
        ensureInBounds(pos, Byte.BYTES);
        try {
            BlockCacheValue<RefCountedByteBuffer> value = pinBlock(pos);
            if (value == null)
                return readFallbackByte(pos);
            try {
                long offsetInBlock = (base + pos) & mask;
                return value.value().segment().get(LAYOUT_BYTE, offsetInBlock);
            } finally {
                Reference.reachabilityFence(value);
            }
        } catch (IOException e) {
            return readFallbackByte(pos);
        }
    }

    @Override
    public short readShort(long pos) throws IOException {
        ensureInBounds(pos, Short.BYTES);
        try {
            BlockCacheValue<RefCountedByteBuffer> value = pinBlock(pos);
            if (value == null)
                return readFallbackShort(pos);
            try {
                long offsetInBlock = (base + pos) & mask;
                if (offsetInBlock + Short.BYTES > StaticConfigs.CACHE_BLOCK_SIZE) {
                    return readFallbackShort(pos);
                }
                return value.value().segment().get(LE_SHORT, offsetInBlock);
            } finally {
                Reference.reachabilityFence(value);
            }
        } catch (IOException e) {
            return readFallbackShort(pos);
        }
    }

    @Override
    public int readInt(long pos) throws IOException {
        ensureInBounds(pos, Integer.BYTES);
        try {
            BlockCacheValue<RefCountedByteBuffer> value = pinBlock(pos);
            if (value == null)
                return readFallbackInt(pos);
            try {
                long offsetInBlock = (base + pos) & mask;
                if (offsetInBlock + Integer.BYTES > StaticConfigs.CACHE_BLOCK_SIZE) {
                    return readFallbackInt(pos);
                }
                return value.value().segment().get(LE_INT, offsetInBlock);
            } finally {
                Reference.reachabilityFence(value);
            }
        } catch (IOException e) {
            return readFallbackInt(pos);
        }
    }

    @Override
    public long readLong(long pos) throws IOException {
        ensureInBounds(pos, Long.BYTES);
        try {
            BlockCacheValue<RefCountedByteBuffer> value = pinBlock(pos);
            if (value == null)
                return readFallbackLong(pos);
            try {
                long offsetInBlock = (base + pos) & mask;
                if (offsetInBlock + Long.BYTES > StaticConfigs.CACHE_BLOCK_SIZE) {
                    return readFallbackLong(pos);
                }
                return value.value().segment().get(LE_LONG, offsetInBlock);
            } finally {
                Reference.reachabilityFence(value);
            }
        } catch (IOException e) {
            return readFallbackLong(pos);
        }
    }

    /**
     * Validates a read of {@code width} bytes at {@code pos} against the logical slice length before any
     * block is resolved. A pooled block buffer is ALWAYS the full {@code CACHE_BLOCK_SIZE}, so the final
     * block's tail past the logical length holds zero-fill or decrypted footer ciphertext; without this
     * check an out-of-range read would return those bytes as data (silent under unauthenticated AES-CTR),
     * while the disk-fallback path throws — so the two paths would disagree on EOF. Called FIRST in every
     * reader, before the {@code try} that falls back to disk, so the {@link EOFException} propagates rather
     * than being swallowed into a fallback. Written as {@code width > len - pos} so it cannot overflow.
     */
    private void ensureInBounds(long pos, int width) throws IOException {
        if (pos < 0 || width > len - pos) {
            throw new EOFException("read past EOF (pos=" + pos + ", width=" + width + ", len=" + len + "): " + path);
        }
    }

    /**
     * Resolve the block containing the given position from L1 → L2 cache.
     * Returns the {@link BlockCacheValue} wrapper (or null if unavailable) rather than a bare
     * {@link MemorySegment}: callers must keep the wrapper reachable across the native read via
     * {@link Reference#reachabilityFence}, otherwise the GC could collect it and its Cleaner free the
     * block's off-heap memory mid-read (use-after-free → SIGSEGV or recycled bytes). Handing back only the
     * segment made that impossible, since the segment holds no reference to the wrapper.
     */
    private BlockCacheValue<RefCountedByteBuffer> pinBlock(long pos) throws IOException {
        long absPos = base + pos;
        long blockOffset = absPos & ~mask;
        long blockId = blockOffset >>> StaticConfigs.CACHE_BLOCK_SIZE_POWER;

        // L1 lookup (lock-free, two array reads)
        if (radixTable != null) {
            BlockCacheValue<RefCountedByteBuffer> entry = radixTable.get(blockId);
            if (entry != null) {
                if (registry != null)
                    registry.recordHit();
                return entry;
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
            return v;
        }

        // L2 miss — try to load
        BlockCacheValue<RefCountedByteBuffer> loaded = cache.getOrLoad(key);
        if (loaded != null) {
            if (radixTable != null && !loaded.isTransient()) {
                radixTable.put(blockId, loaded);
            }
            return loaded;
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
