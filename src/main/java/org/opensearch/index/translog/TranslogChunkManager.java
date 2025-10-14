/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.opensearch.index.store.cipher.AesCipherFactory.computeOffsetIVForAesGcmEncrypted;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Key;

import javax.crypto.Cipher;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.codecs.CodecUtil;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesGcmCipherFactory;
import org.opensearch.index.store.key.KeyResolver;

/**
 * Manages 8KB encrypted chunks for translog files using AES-GCM authentication.
 * Handles chunk positioning, encryption, decryption, and I/O operations.
 * 
 * This class separates chunking logic from FileChannel delegation, making the code
 * more maintainable and testable.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "Channel operations required for chunk-based encryption")
public class TranslogChunkManager {

    private static final Logger logger = LogManager.getLogger(TranslogChunkManager.class);

    // GCM chunk constants
    public static final int GCM_CHUNK_SIZE = 8192;                                    // 8KB data per chunk
    public static final int GCM_TAG_SIZE = AesGcmCipherFactory.GCM_TAG_LENGTH;       // 16 bytes auth tag
    public static final int CHUNK_WITH_TAG_SIZE = GCM_CHUNK_SIZE + GCM_TAG_SIZE;     // 8208 bytes max

    // Thread-local buffer pool for reducing allocations
    private static final ThreadLocal<ByteBuffer> CHUNK_BUFFER_POOL = ThreadLocal.withInitial(
        () -> ByteBuffer.allocate(CHUNK_WITH_TAG_SIZE)
    );
    private static final ThreadLocal<ByteBuffer> TRANSFER_BUFFER_POOL = ThreadLocal.withInitial(
        () -> ByteBuffer.allocate(GCM_CHUNK_SIZE)
    );
    private static final ThreadLocal<byte[]> TEMP_ARRAY_POOL = ThreadLocal.withInitial(
        () -> new byte[GCM_CHUNK_SIZE]
    );

    private final FileChannel delegate;
    private final KeyResolver keyResolver;
    private final Path filePath;
    private final String translogUUID;

    // Header size - calculated exactly using TranslogHeader.headerSizeInBytes()
    private volatile int actualHeaderSize = -1;

    // Streaming cipher state for write operations
    private Cipher currentCipher;
    private int currentBlockNumber = 0;
    private int currentBlockBytesWritten = 0;
    private static final int BLOCK_SIZE = 8192; // 8KB blocks
    private long fileWritePosition = 0;

    /**
     * Helper class for chunk position mapping
     */
    public static class ChunkInfo {
        public final int chunkIndex;           // Which chunk (0, 1, 2, ...)
        public final int offsetInChunk;        // Position within the 8KB chunk
        public final long diskPosition;        // Actual file position of chunk start

        public ChunkInfo(int chunkIndex, int offsetInChunk, long diskPosition) {
            this.chunkIndex = chunkIndex;
            this.offsetInChunk = offsetInChunk;
            this.diskPosition = diskPosition;
        }
    }

    /**
     * Creates a new TranslogChunkManager for managing encrypted chunks.
     *
     * @param delegate the underlying FileChannel for actual I/O operations
     * @param keyResolver the key and IV resolver for encryption operations
     * @param filePath the file path (used for logging and debugging)
     * @param translogUUID the translog UUID for exact header size calculation
     */
    public TranslogChunkManager(FileChannel delegate, KeyResolver keyResolver, Path filePath, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.filePath = filePath;
        this.translogUUID = translogUUID;
    }

    /**
     * Determines the exact header size using local calculation to avoid cross-classloader access.
     * This replicates the exact same logic as TranslogHeader.headerSizeInBytes() method.
     */
    public int determineHeaderSize() {
        if (actualHeaderSize > 0) {
            return actualHeaderSize;
        }

        String fileName = filePath.getFileName().toString();
        if (fileName.endsWith(".tlog")) {
            actualHeaderSize = calculateTranslogHeaderSize(translogUUID);
//            logger.debug("Calculated exact header size: {} bytes for {} with UUID: {}", actualHeaderSize, filePath, translogUUID);
        } else {
            // Non-translog files (.ckp) don't need encryption anyway
            actualHeaderSize = 0;
//            logger.debug("Non-translog file {}, header size: 0", filePath);
        }

        return actualHeaderSize;
    }

    /**
     * Local implementation of TranslogHeader.headerSizeInBytes() to avoid cross-classloader access issues.
     * This replicates the exact same calculation as the original method.
     *
     * @param translogUUID the translog UUID
     * @return the header size in bytes
     */
    private static int calculateTranslogHeaderSize(String translogUUID) {
        int uuidLength = translogUUID.getBytes(StandardCharsets.UTF_8).length;

        // Calculate header size using official TranslogHeader constants
        int size = CodecUtil.headerLength(TranslogHeader.TRANSLOG_CODEC); // Lucene codec header
        size += Integer.BYTES + uuidLength; // uuid length field + uuid bytes

        if (TranslogHeader.CURRENT_VERSION >= TranslogHeader.VERSION_PRIMARY_TERM) {
            size += Long.BYTES;    // primary term
            size += Integer.BYTES; // checksum
        }

        return size;
    }

    /**
     * Maps a file position to chunk information.
     */
    public ChunkInfo getChunkInfo(long filePosition) {
        long dataPosition = filePosition - determineHeaderSize();
        int chunkIndex = (int) (dataPosition / GCM_CHUNK_SIZE);
        int offsetInChunk = (int) (dataPosition % GCM_CHUNK_SIZE);
        long diskPosition = determineHeaderSize() + ((long) chunkIndex * CHUNK_WITH_TAG_SIZE);
        return new ChunkInfo(chunkIndex, offsetInChunk, diskPosition);
    }

    /**
     * Checks if we can read a chunk at the given disk position.
     * Returns false for write-only channels or if chunk doesn't exist.
     */
    public boolean canReadChunk(long diskPosition) {
        try {
            // Check if position is beyond current file size (new chunk)
            if (diskPosition >= delegate.size()) {
                return false;
            }

            // Test if channel is readable by attempting a zero-byte read
            ByteBuffer testBuffer = ByteBuffer.allocate(0);
            delegate.read(testBuffer, diskPosition);
            return true;

        } catch (NonReadableChannelException e) {
            // Channel is write-only
            return false;
        } catch (IOException e) {
            // Other read errors - assume can't read
            return false;
        }
    }

    /**
     * Reads and decrypts a complete chunk from disk.
     * Returns empty array if chunk doesn't exist or channel is write-only.
     */
    public byte[] readAndDecryptChunk(int chunkIndex) throws IOException {
//        System.out.println("[DEBUG] readAndDecryptChunk: chunkIndex=" + chunkIndex);
        try {
            // Calculate disk position for this chunk
            long diskPosition = determineHeaderSize() + ((long) chunkIndex * CHUNK_WITH_TAG_SIZE);

            // Check if chunk exists and we can read it
            if (!canReadChunk(diskPosition)) {
//                System.out.println("[DEBUG] Cannot read chunk at position " + diskPosition);
                return new byte[0]; // New chunk or write-only channel
            }

            // Read encrypted chunk + tag from disk using pooled buffer
            ByteBuffer buffer = CHUNK_BUFFER_POOL.get();
            buffer.clear();
            int bytesRead = delegate.read(buffer, diskPosition);
//            System.out.println("[DEBUG] Read " + bytesRead + " bytes from disk at position " + diskPosition);
            if (bytesRead <= GCM_TAG_SIZE) {
                return new byte[0]; // Empty or invalid chunk
            }

            // Extract encrypted data with tag
            byte[] encryptedWithTag = new byte[bytesRead];
            buffer.flip();
            buffer.get(encryptedWithTag);

            // Use existing key management
            Key key = keyResolver.getDataKey();
            byte[] baseIV = keyResolver.getIvBytes();

            // Use existing IV computation for this chunk
            long chunkOffset = (long) chunkIndex * GCM_CHUNK_SIZE;
            byte[] chunkIV = computeOffsetIVForAesGcmEncrypted(baseIV, chunkOffset);

            // Use existing GCM decryption with authentication
            byte[] decrypted = AesGcmCipherFactory.decryptWithTag(key, chunkIV, encryptedWithTag);
//            System.out.println("[DEBUG] Decrypted " + decrypted.length + " bytes from chunk " + chunkIndex);
            return decrypted;

        } catch (Exception e) {
            throw new IOException("Failed to decrypt chunk " + chunkIndex, e);
        }
    }

    /**
     * Encrypts and writes a complete chunk to disk.
     */
    public void encryptAndWriteChunk(int chunkIndex, byte[] plainData) throws IOException {
        try {
            // Use existing key management
            Key key = keyResolver.getDataKey();
            byte[] baseIV = keyResolver.getIvBytes();

            // Use existing IV computation for this chunk
            long chunkOffset = (long) chunkIndex * GCM_CHUNK_SIZE;
            byte[] chunkIV = computeOffsetIVForAesGcmEncrypted(baseIV, chunkOffset);

            // Use existing GCM encryption (includes authentication tag)
            byte[] encryptedWithTag = AesGcmCipherFactory.encryptWithTag(key, chunkIV, plainData, plainData.length);

            // Write to disk at chunk position
            long diskPosition = determineHeaderSize() + ((long) chunkIndex * CHUNK_WITH_TAG_SIZE);
            ByteBuffer buffer = ByteBuffer.wrap(encryptedWithTag);
            delegate.write(buffer, diskPosition);

        } catch (Exception e) {
            throw new IOException("Failed to encrypt chunk " + chunkIndex + " in file " + filePath, e);
        }
    }

    /**
     * Reads data from encrypted chunks at the specified position.
     * This method handles chunk boundary crossing and decryption.
     *
     * @param dst the buffer to read data into
     * @param position the file position to read from
     * @return the number of bytes read
     * @throws IOException if reading fails
     */
    public int readFromChunks(ByteBuffer dst, long position) throws IOException {
        if (dst.remaining() == 0) {
            return 0;
        }

        int headerSize = determineHeaderSize();

        // Header reads remain unchanged
        if (position < headerSize) {
            return delegate.read(dst, position);
        }

        // Chunk-based reading for encrypted data
        ChunkInfo chunkInfo = getChunkInfo(position);

        // Read and decrypt the needed chunk
        byte[] decryptedChunk = readAndDecryptChunk(chunkInfo.chunkIndex);

        // Extract requested data from decrypted chunk
        int available = Math.max(0, decryptedChunk.length - chunkInfo.offsetInChunk);
        int toRead = Math.min(dst.remaining(), available);

        if (toRead > 0) {
            dst.put(decryptedChunk, chunkInfo.offsetInChunk, toRead);
        }

        return toRead;
    }

    /**
     * Writes data using streaming cipher with auto block management.
     * Handles block boundaries by finalizing cipher and writing tag inline.
     *
     * @param src the buffer containing data to write
     * @param position the file position to write to
     * @return the number of bytes written
     * @throws IOException if writing fails
     */
    public int writeToChunks(ByteBuffer src, long position) throws IOException {
//        System.out.println("[DEBUG] writeToChunks: src.remaining=" + src.remaining() + ", position=" + position);
        if (src.remaining() == 0) {
            return 0;
        }

        int headerSize = determineHeaderSize();

        // Header writes remain unencrypted - write at exact position
        if (position < headerSize) {
            int written = delegate.write(src, position);
//            System.out.println("[DEBUG] Header write: " + written + " bytes at position " + position);
            return written;
        }

        if (fileWritePosition == 0) {
            fileWritePosition = headerSize;
        }

        int totalWritten = 0;

        while (src.hasRemaining()) {
//            System.out.println("[DEBUG] Loop: currentCipher=" + (currentCipher != null ? "active" : "null") +
//                ", currentBlockBytesWritten=" + currentBlockBytesWritten + ", BLOCK_SIZE=" + BLOCK_SIZE);
            // Initialize cipher on first write or when block is full
            if (currentCipher == null || currentBlockBytesWritten >= BLOCK_SIZE) {
                if (currentCipher != null) {
                    // Block is full - finalize and write tag
//                    System.out.println("[DEBUG] Block full, finalizing...");
                    finalizeCurrentBlock();
                }
                // Start new block
                initializeBlockCipher(currentBlockNumber++);
            }

            // Write what fits in current block
            int toWrite = Math.min(src.remaining(), BLOCK_SIZE - currentBlockBytesWritten);
//            System.out.println("[DEBUG] Writing " + toWrite + " bytes to current block");

            // Use pooled array to avoid allocation
            byte[] plainData = TEMP_ARRAY_POOL.get();
            src.get(plainData, 0, toWrite);

            // Stream encrypt using current cipher (no tag yet)
            byte[] encrypted = AesGcmCipherFactory.encryptWithoutTag(
                    position + totalWritten,
                    currentCipher,
                    plainData,
                    toWrite
            );
//            System.out.println("[DEBUG] Encrypted " + encrypted.length + " bytes");

            // Write encrypted data immediately at tracked position
            int written = delegate.write(ByteBuffer.wrap(encrypted), fileWritePosition);
            fileWritePosition += written;

            currentBlockBytesWritten += toWrite;
            totalWritten += toWrite;
//            System.out.println("[DEBUG] Total written so far: " + totalWritten + ", currentBlockBytesWritten=" + currentBlockBytesWritten);
        }

//        System.out.println("[DEBUG] writeToChunks completed: totalWritten=" + totalWritten);
        return totalWritten;
    }

    /**
     * Transfers data from encrypted chunks to a target channel.
     * This method decrypts data during transfer.
     *
     * @param position the starting position in the source
     * @param count the number of bytes to transfer
     * @param target the target channel to write to
     * @return the number of bytes transferred
     * @throws IOException if transfer fails
     */
    public long transferFromChunks(long position, long count, WritableByteChannel target) throws IOException {
        long transferred = 0;
        long remaining = count;
        ByteBuffer buffer = TRANSFER_BUFFER_POOL.get();
        buffer.clear();

        while (remaining > 0 && transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), remaining);
            buffer.limit(toRead);

            int bytesRead = readFromChunks(buffer, position + transferred);
            if (bytesRead <= 0) {
                break;
            }

            buffer.flip();
            int bytesWritten = target.write(buffer);
            transferred += bytesWritten;
            remaining -= bytesWritten;

            if (bytesWritten < bytesRead) {
                break;
            }
        }

        return transferred;
    }

    /**
     * Transfers data from a source channel to encrypted chunks.
     * This method encrypts data during transfer.
     *
     * @param src the source channel to read from
     * @param position the starting position in the target
     * @param count the number of bytes to transfer
     * @return the number of bytes transferred
     * @throws IOException if transfer fails
     */
    public long transferToChunks(ReadableByteChannel src, long position, long count) throws IOException {
        long transferred = 0;
        long remaining = count;
        ByteBuffer buffer = TRANSFER_BUFFER_POOL.get();
        buffer.clear();

        while (remaining > 0 && transferred < count) {
            buffer.clear();
            int toRead = (int) Math.min(buffer.remaining(), remaining);
            buffer.limit(toRead);

            int bytesRead = src.read(buffer);
            if (bytesRead <= 0) {
                break;
            }

            buffer.flip();
            int bytesWritten = writeToChunks(buffer, position + transferred);
            transferred += bytesWritten;
            remaining -= bytesWritten;

            if (bytesWritten < bytesRead) {
                break;
            }
        }

        return transferred;
    }

    /**
     * Initialize GCM cipher for a new block
     */
    private void initializeBlockCipher(int blockNumber) throws IOException {
//        System.out.println("[DEBUG] Initializing cipher for block " + blockNumber + " at file " + filePath);
        Key key = keyResolver.getDataKey();
        byte[] baseIV = keyResolver.getIvBytes();
        long offset = (long) blockNumber * BLOCK_SIZE;

        this.currentCipher = AesGcmCipherFactory.initializeGCMCipher(key, baseIV, offset);
        this.currentBlockNumber = blockNumber;
        this.currentBlockBytesWritten = 0;
//        System.out.println("[DEBUG] Cipher initialized for block " + blockNumber + ", offset=" + offset);
    }

    /**
     * Finalize current block and write tag inline
     */
    private void finalizeCurrentBlock() throws IOException {
        if (currentCipher == null) {
//            System.out.println("[DEBUG] finalizeCurrentBlock called but currentCipher is null");
            return;
        }
//        System.out.println("[DEBUG] Finalizing block " + currentBlockNumber + " with " + currentBlockBytesWritten + " bytes written");
        byte[] tag = AesGcmCipherFactory.finalizeAndGetTag(currentCipher);
        int written = delegate.write(ByteBuffer.wrap(tag), fileWritePosition);
        fileWritePosition += written;
//        System.out.println("[DEBUG] Block " + currentBlockNumber + " finalized and tag written at position " + (fileWritePosition - written));
    }

    /**
     * Close and finalize last block
     */
    public void close() throws IOException {
//        System.out.println("[DEBUG] Closing TranslogChunkManager for file " + filePath +
//            ", currentCipher=" + (currentCipher != null ? "active" : "null") +
//            ", bytesWritten=" + currentBlockBytesWritten);
        if (currentCipher != null) {
            finalizeCurrentBlock();
            currentCipher = null;
//            System.out.println("[DEBUG] Last block finalized on close");
        } else {
//            System.out.println("[DEBUG] No active cipher to finalize on close");
        }
    }
}
