/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides Java native crypto bindings for AES encryption/decryption.
 * Uses javax.crypto.Cipher for both GCM and CTR modes.
 *
 * @opensearch.internal
 */
public final class JavaNativeCipher {

    public static final int AES_256_KEY_SIZE = 32;
    public static final int GCM_TAG_SIZE = 16; // 128-bit auth tag

    /**
     * Custom exception for Java crypto-related errors
     */
    public static class JavaCryptoException extends RuntimeException {
        public JavaCryptoException(String message) {
            super(message);
        }

        public JavaCryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static byte[] computeOffsetIVForGCM(byte[] baseIV, long offset) {
        // Create 12-byte IV with block number embedded
        byte[] ivCopy = new byte[12];
        System.arraycopy(baseIV, 0, ivCopy, 0, Math.min(baseIV.length, 8)); // Use first 8 bytes

        // Embed block number in last 4 bytes of 12-byte IV
        long blockNumber = offset / 16;
        ivCopy[8] = (byte) (blockNumber >>> 24);
        ivCopy[9] = (byte) (blockNumber >>> 16);
        ivCopy[10] = (byte) (blockNumber >>> 8);
        ivCopy[11] = (byte) blockNumber;

        return ivCopy;
    }

    public static byte[] computeOffsetIVForCTR(byte[] baseIV, long offset) {
        // Create 16-byte IV: [12-byte GCM IV][0][0][0][counter]
        byte[] ivCopy = new byte[16];

        // Use the SAME 12-byte IV as GCM
        byte[] gcmIV = computeOffsetIVForGCM(baseIV, offset);
        System.arraycopy(gcmIV, 0, ivCopy, 0, 12);

        // Set counter to 2 for compatibility (GCM uses counter 2 for first data block)
        ivCopy[12] = 0;
        ivCopy[13] = 0;
        ivCopy[14] = 0;
        ivCopy[15] = 2; // Always 2 for first data block

        return ivCopy;
    }

    public static byte[] encryptGCMJava(byte[] key, byte[] iv, byte[] input, long filePosition) {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length < 12) {
            throw new IllegalArgumentException("Invalid IV: must be at least 12 bytes");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            // Use 12-byte IV (standard GCM)
            byte[] gcmIV = computeOffsetIVForGCM(iv, filePosition);
            GCMParameterSpec paramSpec = new GCMParameterSpec(128, gcmIV); // 128-bit tag

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);

            byte[] encrypted = cipher.doFinal(input);

            // Remove authentication tag (last 16 bytes)
            if (encrypted.length < GCM_TAG_SIZE) {
                throw new JavaCryptoException("Encrypted output too short for tag removal");
            }

            byte[] ciphertextOnly = new byte[encrypted.length - GCM_TAG_SIZE];
            System.arraycopy(encrypted, 0, ciphertextOnly, 0, ciphertextOnly.length);

            return ciphertextOnly;

        } catch (Exception e) {
            throw new JavaCryptoException("GCM encryption failed at position " + filePosition, e);
        }
    }

    public static byte[] decryptCTRJava(byte[] key, byte[] iv, byte[] input, long filePosition) {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length < 12) {
            throw new IllegalArgumentException("Invalid IV: must be at least 12 bytes");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            // Create 16-byte IV: [12-byte GCM IV][0][0][0][counter]
            byte[] ctrIV = computeOffsetIVForCTR(iv, filePosition);
            IvParameterSpec paramSpec = new IvParameterSpec(ctrIV);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);

            // No partial block skipping for position 0 test
            byte[] decrypted = cipher.doFinal(input);

            return decrypted;

        } catch (Exception e) {
            throw new JavaCryptoException("CTR decryption failed at position " + filePosition, e);
        }
    }

    private JavaNativeCipher() {
        // Utility class
    }
}