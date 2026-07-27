/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import static org.opensearch.index.store.cipher.AesCipherFactory.ALGORITHM;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.BufferedIndexInput;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.RandomAccessInput;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTable;
import org.opensearch.index.store.bufferpoolfs.RadixBlockTableRegistry;
import org.opensearch.index.store.bufferpoolfs.StaticConfigs;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.cipher.EncryptionAlgorithm;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;

/**
 * An IndexInput implementation that decrypts data for reading
 *
 * @opensearch.internal
 */
public final class CryptoBufferedIndexInput extends BufferedIndexInput {
    private static final byte[] ZERO_SKIP = new byte[1 << AesCipherFactory.AES_BLOCK_SIZE_BYTES_IN_POWER];
    private static final ByteBuffer EMPTY_BYTEBUFFER = ByteBuffer.allocate(0);
    private static final int CHUNK_SIZE = 16_384;

    /**
     * File extensions whose random access pattern (many tiny reads during merges) makes
     * block-cache overhead worse than direct NIO decrypt. These bypass the cache even in
     * randomAccessSlice().
     */
    private static final Set<String> RANDOM_ACCESS_BYPASS_EXTS = Set
        .of(
            "dvd",
            "dvm",         // doc-values (data + metadata)
            "kdd",
            "kdi",
            "kdm",  // points / BKD
            "nvd",
            "nvm"          // norms
        );

    private final FileChannel channel;
    // Channel-ownership flag: true means this instance shares a FileChannel owned by another
    // instance and must NOT close it. Set on slices and on clones (see clone()). Non-final
    // because Object.clone() copies the value bitwise and clone() must reassign it to true.
    // Same pattern Lucene's NIOFSDirectory.NIOFSIndexInput uses.
    private boolean isClone;
    // Slice flag: true only for sub-range windows created by slice(). Drives length():
    // a slice reports its exact passed-in length, while a whole-file instance (root or a
    // clone of the root) subtracts the trailing encryption footer. Kept SEPARATE from
    // isClone so a clone (which shares the channel, isClone=true) still reports whole-file
    // length (isSlice=false) instead of wrongly including the footer.
    private final boolean isSlice;
    private final long off;
    private final long end;
    private final KeyResolver keyResolver;
    private final SecretKeySpec keySpec;
    private final byte[] masterKey;
    private final byte[] messageId;
    private final int footerLength;
    private final long frameSize;
    private final int frameSizePower;
    private final EncryptionAlgorithm algorithm;
    private final EncryptionMetadataCache encryptionMetadataCache;

    private ByteBuffer tmpBuffer = EMPTY_BYTEBUFFER;

    private final String normalizedFilePath;
    private final Path filePath;

    /** Block cache for pool-backed randomAccessSlice. Null if not available. */
    private final BlockCache<RefCountedByteBuffer> blockCache;
    /**
     * Per-file L1 RadixBlockTable. Acquired lazily on first randomAccessSlice call.
     * Null until then, or when no registry is wired.
     */
    private RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixBlockTable;
    /** Registry for L1 table lifecycle. Only set on primary (non-clone) instances. */
    private final RadixBlockTableRegistry radixBlockTableRegistry;

    public CryptoBufferedIndexInput(
        String resourceDesc,
        FileChannel fc,
        IOContext context,
        KeyResolver keyResolver,
        Path filePath,
        EncryptionMetadataCache encryptionMetadataCache
    )
        throws IOException {
        this(resourceDesc, fc, context, keyResolver, filePath, encryptionMetadataCache, null, null);
    }

    /**
     * Creates a CryptoBufferedIndexInput with optional block cache support for randomAccessSlice.
     *
     * <p>When {@code blockCache} and {@code radixBlockTableRegistry} are provided, the
     * {@link #randomAccessSlice} method will use the shared block cache for random access reads
     * (e.g., bloom filters, term dictionaries during search). Sequential reads still use the
     * standard NIO decrypt path without any pool/cache interaction.
     *
     * @param resourceDesc description for debugging
     * @param fc the open FileChannel
     * @param context the IOContext
     * @param keyResolver key resolver for decryption
     * @param filePath the file path
     * @param encryptionMetadataCache cache for encryption metadata
     * @param blockCache shared block cache (may be null)
     * @param radixBlockTableRegistry shared L1 table registry (may be null)
     */
    public CryptoBufferedIndexInput(
        String resourceDesc,
        FileChannel fc,
        IOContext context,
        KeyResolver keyResolver,
        Path filePath,
        EncryptionMetadataCache encryptionMetadataCache,
        BlockCache<RefCountedByteBuffer> blockCache,
        RadixBlockTableRegistry radixBlockTableRegistry
    )
        throws IOException {
        super(resourceDesc, context);
        this.channel = fc;
        this.off = 0L;
        this.end = fc.size();
        this.keyResolver = keyResolver;
        this.isClone = false;
        this.isSlice = false;
        this.filePath = filePath;
        this.normalizedFilePath = EncryptionMetadataCache.normalizePath(filePath);
        this.encryptionMetadataCache = encryptionMetadataCache;
        this.blockCache = blockCache;
        this.radixBlockTable = null; // acquired lazily on first randomAccessSlice call
        this.radixBlockTableRegistry = radixBlockTableRegistry;

        // Get master key first
        this.masterKey = keyResolver.getDataKey().getEncoded();

        // Read footer (readViaFileChannel caches an inode-stamped metadata entry when the inode is stable).
        // Derive fields straight from THIS footer rather than re-fetching via the path-based
        // getOrLoadMetadata: a re-fetch would re-stat the name and could bind this reader's footer to a
        // concurrently-recreated inode (TOCTOU). The footer is authoritative for this open channel.
        EncryptionFooter footer = EncryptionFooter.readViaFileChannel(normalizedFilePath, channel, masterKey, encryptionMetadataCache);
        this.messageId = footer.getMessageId();
        this.frameSize = footer.getFrameSize();
        this.frameSizePower = footer.getFrameSizePower();
        this.algorithm = EncryptionAlgorithm.fromId(footer.getAlgorithmId());
        this.keySpec = new SecretKeySpec(HkdfKeyDerivation.deriveFileKey(masterKey, this.messageId), ALGORITHM);

        // Calculate footer length
        this.footerLength = footer.getFooterLength();
    }

    public CryptoBufferedIndexInput(
        String resourceDesc,
        FileChannel fc,
        long off,
        long length,
        int bufferSize,
        KeyResolver keyResolver,
        SecretKeySpec keySpec,
        int footerLength,
        long frameSize,
        int frameSizePower,
        short algorithmId,
        byte[] masterKey,
        byte[] messageId,
        String normalizedFilePath,
        EncryptionMetadataCache encryptionMetadataCache,
        BlockCache<RefCountedByteBuffer> blockCache,
        RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixBlockTable
    )
        throws IOException {
        super(resourceDesc, bufferSize);
        this.channel = fc;
        this.off = off;
        this.end = off + length;
        this.isClone = true;
        this.isSlice = true;
        this.keyResolver = keyResolver;
        this.keySpec = keySpec;
        this.footerLength = footerLength;
        this.frameSize = frameSize;
        this.frameSizePower = frameSizePower;
        this.algorithm = EncryptionAlgorithm.fromId(algorithmId);
        this.masterKey = masterKey;
        this.messageId = messageId;
        this.filePath = null; // slices don't own a path
        this.normalizedFilePath = normalizedFilePath;
        this.encryptionMetadataCache = encryptionMetadataCache;
        this.blockCache = blockCache;
        this.radixBlockTable = radixBlockTable; // share parent's table
        this.radixBlockTableRegistry = null; // slices don't call release()
    }

    @Override
    public void close() throws IOException {
        if (!isClone) {
            channel.close();
            // Release the L1 RadixBlockTable only if it was acquired (lazily on randomAccessSlice)
            if (radixBlockTableRegistry != null && radixBlockTable != null && filePath != null) {
                radixBlockTableRegistry.release(filePath.toAbsolutePath().normalize());
            }
        }
    }

    @Override
    public CryptoBufferedIndexInput clone() {
        CryptoBufferedIndexInput clone = (CryptoBufferedIndexInput) super.clone();
        clone.tmpBuffer = EMPTY_BYTEBUFFER;
        // Object.clone() is a shallow bitwise copy — the clone inherits the parent's
        // isClone value. If we don't set this here, a clone of the root would have
        // isClone=false and its close() would close the shared FileChannel, causing
        // ClosedChannelException on any concurrent read via the parent or a sibling
        // clone/slice. Matches Lucene NIOFSDirectory.NIOFSIndexInput.clone().
        clone.isClone = true;
        return clone;
    }

    @Override
    public IndexInput slice(String sliceDescription, long offset, long length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > this.length()) {
            throw new IllegalArgumentException(
                "slice() " + sliceDescription + " out of bounds: offset=" + offset + ", length=" + length + ", fileLength=" + this.length()
            );
        }
        return new CryptoBufferedIndexInput(
            getFullSliceDescription(sliceDescription),
            channel,
            off + offset,
            length,
            getBufferSize(),
            keyResolver,
            keySpec,
            footerLength,
            frameSize,
            frameSizePower,
            algorithm.getAlgorithmId(),
            masterKey,
            messageId,
            normalizedFilePath,
            encryptionMetadataCache,
            blockCache,
            radixBlockTable  // share L1 table; slice doesn't call registry.release()
        );
    }

    @Override
    public long length() {
        // Footer handling is driven by isSlice (NOT isClone): a slice was already given an
        // exact sub-range length, so report it verbatim. A whole-file instance — the root OR
        // a clone of the root — must subtract the trailing encryption footer so callers only
        // see logical data length. (A clone has isClone=true for channel-ownership but
        // isSlice=false, so it correctly lands in the footer-excluding branch here.)
        if (isSlice) {
            return end - off;  // slice: exact length passed in
        } else {
            return end - off - footerLength;  // whole file (root or clone): exclude footer
        }
    }

    @SuppressForbidden(reason = "FileChannel#read is efficient and used intentionally")
    private int read(ByteBuffer dst, long position) throws IOException {
        if (tmpBuffer == EMPTY_BYTEBUFFER) {
            tmpBuffer = ByteBuffer.allocate(CHUNK_SIZE);
        }

        long frameNumber = position >>> frameSizePower;
        long offsetWithinFrame = position & ((1L << frameSizePower) - 1);
        long frameEnd = (frameNumber + 1) << frameSizePower;
        int maxReadInFrame = (int) Math.min(dst.remaining(), frameEnd - position);

        tmpBuffer.clear().limit(maxReadInFrame);
        int bytesRead = channel.read(tmpBuffer, position);
        if (bytesRead == -1) {
            return -1;
        }
        tmpBuffer.flip();

        try {
            Cipher cipher = algorithm.getDecryptionCipher();
            byte[] frameIV = AesCipherFactory
                .computeFrameIV(masterKey, messageId, frameNumber, offsetWithinFrame, this.normalizedFilePath, encryptionMetadataCache);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(frameIV));

            // skip partial AES block within frame if needed
            int skipBytes = (int) (offsetWithinFrame & ((1 << AesCipherFactory.AES_BLOCK_SIZE_BYTES_IN_POWER) - 1));
            if (skipBytes > 0) {
                cipher.update(ZERO_SKIP, 0, skipBytes);
            }

            // decrypt into dst
            return (end - position > bytesRead) ? cipher.update(tmpBuffer, dst) : cipher.doFinal(tmpBuffer, dst);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException
            | InvalidKeyException ex) {
            // A cipher failure on the niofs read path (per-frame decrypt) — meter it via the existing error flow
            // (crypto.error.total{error_type=niofs_decrypt_failure}) so a systemic decrypt fault surfaces as a
            // signal rather than only an IOException that Lucene may surface later as a CorruptIndexException.
            CryptoMetricsService.getInstance().recordError(ErrorType.NIOFS_DECRYPT_FAILURE);
            throw new IOException("Failed to decrypt block at position " + position, ex);
        }
    }

    @Override
    protected void readInternal(ByteBuffer b) throws IOException {
        long pos = getFilePointer() + off;
        if (pos + b.remaining() > end) {
            throw new EOFException("read past EOF: pos=" + pos + ", end=" + end);
        }

        int readLength = b.remaining();
        while (readLength > 0) {
            final int toRead = Math.min(CHUNK_SIZE, readLength);
            b.limit(b.position() + toRead);
            final int bytesRead = read(b, pos);

            if (bytesRead < 0) {
                throw new EOFException("Unexpected EOF while reading decrypted data at pos=" + pos);
            }

            pos += bytesRead;
            readLength -= bytesRead;
        }
    }

    @Override
    protected void seekInternal(long pos) throws IOException {
        if (pos > length()) {
            throw new EOFException("seek past EOF: pos=" + pos + ", length=" + length());
        }
    }

    // ---- randomAccessSlice: selective block cache usage for random access patterns ----

    private static boolean isRandomAccessBypassFile(Path path) {
        if (path == null)
            return false;
        String name = path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot < 0)
            return false;
        return RANDOM_ACCESS_BYPASS_EXTS.contains(name.substring(dot + 1));
    }

    /**
     * Override randomAccessSlice to use the shared block cache for random access reads.
     *
     * <p>Sequential reads (readByte, readBytes, slice)
     * use the standard NIO decrypt path without any pool/cache interaction. But when Lucene asks for
     * a {@link RandomAccessInput} (used for bloom filters, term dictionaries, postings during search),
     * we route through the block cache for fast repeated random reads.
     *
     * <p>Files in {@link #RANDOM_ACCESS_BYPASS_EXTS} (doc-values, BKD, norms) bypass the cache even
     * here because their many-tiny-random-reads pattern during merges makes cache overhead worse.
     */
    @Override
    @SuppressWarnings("unchecked")
    public RandomAccessInput randomAccessSlice(long offset, long length) throws IOException {
        if (blockCache == null || filePath == null) {
            return super.randomAccessSlice(offset, length);
        }
        // Bypass for doc-values, points/BKD, norms — too many small random reads during merges
        if (isRandomAccessBypassFile(filePath)) {
            return super.randomAccessSlice(offset, length);
        }
        try {
            long fileOffset = off + offset;
            int blockSize = StaticConfigs.CACHE_BLOCK_SIZE;
            long blockMask = StaticConfigs.CACHE_BLOCK_MASK;
            long startBlock = fileOffset & ~blockMask;
            long endPos = fileOffset + length;
            int blockCount = (int) ((endPos - startBlock + blockSize - 1) / blockSize);
            Path absPath = filePath.toAbsolutePath().normalize();

            // Lazy acquire: only files that actually use randomAccessSlice get a RadixBlockTable.
            // Sequential-only files never reach here and pay zero overhead.
            if (radixBlockTable == null && radixBlockTableRegistry != null) {
                radixBlockTable = (RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>>) (RadixBlockTable<?>) radixBlockTableRegistry
                    .acquire(absPath);
            }

            // Pre-load missing blocks in the range
            blockCache.loadForPrefetch(absPath, startBlock, blockCount);

            // Create a fallback slice for cross-block reads or cache failures
            IndexInput fallback = slice("randomaccess-fallback", offset, length);
            return new CachedRandomAccessInput(
                absPath,
                fileOffset,
                length,
                blockMask,
                blockCache,
                radixBlockTable,
                radixBlockTableRegistry,
                fallback
            );
        } catch (IOException e) {
            return super.randomAccessSlice(offset, length);
        }
    }

    /**
     * RandomAccessInput backed by block cache with NIO disk fallback.
     * Each read checks L1 (RadixBlockTable, lock-free) first, then L2 (Caffeine), then disk.
     */
    private static final class CachedRandomAccessInput implements RandomAccessInput {
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
}
