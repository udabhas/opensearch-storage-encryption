/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import static org.opensearch.index.store.cipher.AesCipherFactory.CIPHER_POOL;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.index.store.metrics.CryptoMetricsLogger;

/**
 * Hybrid cipher implementation that can use either:
 * 1. Native OpenSSL via Panama (for large operations)
 * 2. Java Cipher API via ByteBuffer (for small operations, better JIT optimization)
 */

@SuppressWarnings("preview")
public class MemorySegmentDecryptor {

    private static final byte[] ZERO_SKIP = new byte[AesCipherFactory.AES_BLOCK_SIZE_BYTES];
    private static final int DEFAULT_MAX_CHUNK_SIZE = 16_384;

    private MemorySegmentDecryptor() {

    }

    public static void decryptInPlace(Arena arena, long addr, long length, byte[] key, byte[] iv, long fileOffset) throws Exception {
        long startTime = System.nanoTime();
        
        // Get thread-local cipher
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, AesCipherFactory.ALGORITHM);
        byte[] ivCopy = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(iv, fileOffset);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        if (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
            cipher.update(ZERO_SKIP, 0, (int) (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
        }

        MemorySegment segment = MemorySegment.ofAddress(addr).reinterpret(length, arena, null);
        ByteBuffer buffer = segment.asByteBuffer();

        final int CHUNK_SIZE = Math.min(DEFAULT_MAX_CHUNK_SIZE, (int) length); // typecast is safe.
        byte[] chunk = new byte[CHUNK_SIZE];
        byte[] decryptedChunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);

            buffer.position(position);
            buffer.get(chunk, 0, size);

            int decryptedLength = cipher.update(chunk, 0, size, decryptedChunk, 0);
            if (decryptedLength > 0) {
                buffer.position(position);
                buffer.put(decryptedChunk, 0, decryptedLength);
            }

            position += size;
        }

        int finalLength = cipher.doFinal(new byte[0], 0, 0, decryptedChunk, 0);
        if (finalLength > 0) {
            buffer.position(position - finalLength);
            buffer.put(decryptedChunk, 0, finalLength);
        }
        
        // Record metrics
        long endTime = System.nanoTime();
        double latencyMs = (endTime - startTime) / 1_000_000.0;
        double throughputBps = length / (latencyMs / 1000.0);
        
        CryptoMetricsLogger.getInstance().recordDecryptionLatency(latencyMs, "MemorySegmentDecrypt");
        CryptoMetricsLogger.getInstance().recordThroughput(throughputBps, "MemorySegmentDecrypt");
        CryptoMetricsLogger.getInstance().recordMemoryUsage(length + CHUNK_SIZE * 2, "MemorySegmentDecrypt");
    }

    public static void decryptInPlace(long addr, long length, byte[] key, byte[] iv, long fileOffset) throws Exception {
        long startTime = System.nanoTime();
        
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, AesCipherFactory.ALGORITHM);
        byte[] ivCopy = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(iv, fileOffset);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        if (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
            cipher.update(ZERO_SKIP, 0, (int) (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
        }

        MemorySegment segment = MemorySegment.ofAddress(addr).reinterpret(length);
        ByteBuffer buffer = segment.asByteBuffer();

        final int CHUNK_SIZE = Math.min(DEFAULT_MAX_CHUNK_SIZE, (int) length); // typecast is safe.
        byte[] chunk = new byte[CHUNK_SIZE];
        byte[] decryptedChunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);

            buffer.position(position);
            buffer.get(chunk, 0, size);

            int decryptedLength = cipher.update(chunk, 0, size, decryptedChunk, 0);
            if (decryptedLength > 0) {
                buffer.position(position);
                buffer.put(decryptedChunk, 0, decryptedLength);
            }

            position += size;
        }

        int finalLength = cipher.doFinal(new byte[0], 0, 0, decryptedChunk, 0);
        if (finalLength > 0) {
            buffer.position(position - finalLength);
            buffer.put(decryptedChunk, 0, finalLength);
        }
        
        // Record metrics
        long endTime = System.nanoTime();
        double latencyMs = (endTime - startTime) / 1_000_000.0;
        double throughputBps = length / (latencyMs / 1000.0);
        
        CryptoMetricsLogger.getInstance().recordDecryptionLatency(latencyMs, "DirectMemoryDecrypt");
        CryptoMetricsLogger.getInstance().recordThroughput(throughputBps, "DirectMemoryDecrypt");
        CryptoMetricsLogger.getInstance().recordMemoryUsage(length + CHUNK_SIZE * 2, "DirectMemoryDecrypt");
    }

    public static void decryptSegment(MemorySegment segment, long fileOffset, byte[] key, byte[] iv, int segmentSize) throws Exception {
        long startTime = System.nanoTime();
        
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, AesCipherFactory.ALGORITHM);
        byte[] ivCopy = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(iv, fileOffset);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivCopy));

        if (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
            cipher.update(ZERO_SKIP, 0, (int) (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
        }

        ByteBuffer buffer = segment.asByteBuffer();
        final int CHUNK_SIZE = Math.min(DEFAULT_MAX_CHUNK_SIZE, segmentSize);
        byte[] chunk = new byte[CHUNK_SIZE];
        byte[] decryptedChunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);

            buffer.position(position);
            buffer.get(chunk, 0, size);

            int decryptedLength = cipher.update(chunk, 0, size, decryptedChunk, 0);
            if (decryptedLength > 0) {
                buffer.position(position);
                buffer.put(decryptedChunk, 0, decryptedLength);
            }

            position += size;
        }
        
        // Record metrics
        long endTime = System.nanoTime();
        double latencyMs = (endTime - startTime) / 1_000_000.0;
        double throughputBps = segmentSize / (latencyMs / 1000.0);
        
        CryptoMetricsLogger.getInstance().recordDecryptionLatency(latencyMs, "SegmentDecrypt");
        CryptoMetricsLogger.getInstance().recordThroughput(throughputBps, "SegmentDecrypt");
        CryptoMetricsLogger.getInstance().recordMemoryUsage(segmentSize + CHUNK_SIZE * 2, "SegmentDecrypt");
    }
    
    /**
     * Frame-based decryption for large files
     */
    public static void decryptInPlaceFrameBased(long addr, long length, byte[] fileKey, byte[] directoryKey, byte[] messageId, long frameSize, long fileOffset) throws Exception {
        long startTime = System.nanoTime();
        long keyStartTime = System.nanoTime();
        
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(fileKey, AesCipherFactory.ALGORITHM);
        
        // Calculate frame-based IV
        byte[] frameIV = AesCipherFactory.computeFrameIV(directoryKey, messageId, (int)(fileOffset / frameSize), fileOffset % frameSize);
        
        long keyEndTime = System.nanoTime();
        CryptoMetricsLogger.getInstance().recordKeyOperationLatency((keyEndTime - keyStartTime) / 1_000_000.0, "FrameIVComputation");
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(frameIV));

        if (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
            cipher.update(ZERO_SKIP, 0, (int) (fileOffset % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
        }

        MemorySegment segment = MemorySegment.ofAddress(addr).reinterpret(length);
        ByteBuffer buffer = segment.asByteBuffer();

        final int CHUNK_SIZE = Math.min(DEFAULT_MAX_CHUNK_SIZE, (int) length);
        byte[] chunk = new byte[CHUNK_SIZE];
        byte[] decryptedChunk = new byte[CHUNK_SIZE];

        int position = 0;
        while (position < buffer.capacity()) {
            int size = Math.min(CHUNK_SIZE, buffer.capacity() - position);

            buffer.position(position);
            buffer.get(chunk, 0, size);

            int decryptedLength = cipher.update(chunk, 0, size, decryptedChunk, 0);
            if (decryptedLength > 0) {
                buffer.position(position);
                buffer.put(decryptedChunk, 0, decryptedLength);
            }

            position += size;
        }

        int finalLength = cipher.doFinal(new byte[0], 0, 0, decryptedChunk, 0);
        if (finalLength > 0) {
            buffer.position(position - finalLength);
            buffer.put(decryptedChunk, 0, finalLength);
        }
        
        // Record metrics
        long endTime = System.nanoTime();
        double latencyMs = (endTime - startTime) / 1_000_000.0;
        double throughputBps = length / (latencyMs / 1000.0);
        
        CryptoMetricsLogger.getInstance().recordDecryptionLatency(latencyMs, "FrameBasedDecrypt");
        CryptoMetricsLogger.getInstance().recordThroughput(throughputBps, "FrameBasedDecrypt");
        CryptoMetricsLogger.getInstance().recordMemoryUsage(length + CHUNK_SIZE * 2, "FrameBasedDecrypt");
    }
}