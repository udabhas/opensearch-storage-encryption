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
        // Get thread-local cipher
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, AesCipherFactory.ALGORITHM);
        // Check if this is frame-based encryption (messageId passed as iv)
        byte[] ivCopy;
        if (iv.length == 16 && isLikelyMessageId(iv)) {
            // Frame-based encryption: iv is actually messageId
            long frameSize = 64L * 1024 * 1024 * 1024; // 64GB default frame size
            int frameNumber = (int)(fileOffset / frameSize);
            long offsetWithinFrame = fileOffset % frameSize;
            ivCopy = AesCipherFactory.computeFrameIV(key, iv, frameNumber, offsetWithinFrame);
        } else {
            // Legacy encryption
            ivCopy = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(iv, fileOffset);
        }

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
    }

    public static void decryptInPlace(long addr, long length, byte[] key, byte[] iv, long fileOffset) throws Exception {
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, AesCipherFactory.ALGORITHM);
        // Check if this is frame-based encryption (messageId passed as iv)
        byte[] ivCopy;
        if (iv.length == 16 && isLikelyMessageId(iv)) {
            // Frame-based encryption: iv is actually messageId
            long frameSize = 64L * 1024 * 1024 * 1024; // 64GB default frame size
            int frameNumber = (int)(fileOffset / frameSize);
            long offsetWithinFrame = fileOffset % frameSize;
            ivCopy = AesCipherFactory.computeFrameIV(key, iv, frameNumber, offsetWithinFrame);
        } else {
            // Legacy encryption
            ivCopy = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(iv, fileOffset);
        }

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
    }

    public static void decryptSegment(MemorySegment segment, long fileOffset, byte[] key, byte[] iv, int segmentSize) throws Exception {
        Cipher cipher = CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(key, AesCipherFactory.ALGORITHM);
        // Check if this is frame-based encryption (messageId passed as iv)
        byte[] ivCopy;
        if (iv.length == 16 && isLikelyMessageId(iv)) {
            // Frame-based encryption: iv is actually messageId
            long frameSize = 64L * 1024 * 1024 * 1024; // 64GB default frame size
            int frameNumber = (int)(fileOffset / frameSize);
            long offsetWithinFrame = fileOffset % frameSize;
            ivCopy = AesCipherFactory.computeFrameIV(key, iv, frameNumber, offsetWithinFrame);
        } else {
            // Legacy encryption
            ivCopy = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(iv, fileOffset);
        }

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

    }
    
    /**
     * Heuristic to detect if the IV parameter is actually a messageId for frame-based encryption.
     * MessageIds are typically more random than regular IVs.
     */
    private static boolean isLikelyMessageId(byte[] iv) {
        // Simple heuristic: check if bytes have sufficient entropy
        // MessageIds from SecureRandom should have high entropy
        int nonZeroBytes = 0;
        int uniqueBytes = 0;
        boolean[] seen = new boolean[256];
        
        for (byte b : iv) {
            if (b != 0) nonZeroBytes++;
            int unsigned = b & 0xFF;
            if (!seen[unsigned]) {
                seen[unsigned] = true;
                uniqueBytes++;
            }
        }
        
        // MessageId should have most bytes non-zero and good variety
        return nonZeroBytes >= 12 && uniqueBytes >= 10;
    }
}
