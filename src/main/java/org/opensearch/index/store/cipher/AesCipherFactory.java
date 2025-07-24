/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Factory utility for creating and initializing Cipher instances
 *
 * This class is tailored for symmetric encryption modes like AES-CTR,
 * where a block counter is appended to the IV.
 *
 * @opensearch.internal
 */
public class AesCipherFactory {

    public enum CipherType {
        GCM("AES/GCM/NoPadding"),
        CTR("AES/CTR/NoPadding");

        private final String transformation;

        CipherType(String transformation) {
            this.transformation = transformation;
        }

        public String getTransformation() {
            return transformation;
        }
    }

    /** AES block size in bytes. Required for counter calculations. */
    public static final int AES_BLOCK_SIZE_BYTES = 16;

    /** Number of bytes used for the counter in the IV (last 4 bytes). */
    public static final int COUNTER_SIZE_BYTES = 4;

    /** Total IV array length (typically 16 bytes for AES). */
    public static final int IV_ARRAY_LENGTH = 16;

    private static final byte[] ZERO_SKIP = new byte[AesCipherFactory.AES_BLOCK_SIZE_BYTES];

    /**
     * Returns a new Cipher instance configured for AES/CTR/NoPadding using the given provider.
     * Defaults to CTR for backward compatibility.
     *
     * @param provider The JCE provider to use (e.g., SunJCE, BouncyCastle)
     * @return A configured {@link Cipher} instance
     * @throws RuntimeException If the algorithm or padding is not supported
     */
    public static Cipher getCipher(Provider provider) {
        return getCipher(CipherType.CTR, provider);
    }

    /**
     * Returns a new Cipher instance configured for the specified cipher type.
     *
     * @param cipherType The cipher type (GCM or CTR)
     * @param provider The JCE provider to use (e.g., SunJCE, BouncyCastle)
     * @return A configured {@link Cipher} instance
     * @throws RuntimeException If the algorithm or padding is not supported
     */
    public static Cipher getCipher(CipherType cipherType, Provider provider) {
        try {
            return Cipher.getInstance(cipherType.getTransformation(), provider);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to get cipher instance for " + cipherType, e);
        }
    }

    /**
     * Initializes a cipher for encryption or decryption, using an IV adjusted for the given position.
     * Defaults to CTR cipher type for backward compatibility.
     *
     * @param cipher The cipher instance to initialize
     * @param key The symmetric key (e.g., AES key)
     * @param iv The base IV, typically 16 bytes long
     * @param opmode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param newPosition The position in the stream to begin processing from
     * @throws RuntimeException If cipher initialization fails
     */
    public static void initCipher(Cipher cipher, Key key, byte[] iv, int opmode, long newPosition) {
        initCipher(CipherType.CTR, cipher, key, iv, opmode, newPosition);
    }

    /**
     * Initializes a cipher for encryption or decryption based on cipher type.
     *
     * @param cipherType The cipher type (GCM or CTR)
     * @param cipher The cipher instance to initialize
     * @param key The symmetric key (e.g., AES key)
     * @param iv The base IV, typically 16 bytes long
     * @param opmode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param newPosition The position in the stream to begin processing from
     * @throws RuntimeException If cipher initialization fails
     */
    public static void initCipher(CipherType cipherType, Cipher cipher, Key key, byte[] iv, int opmode, long newPosition) {
        try {
            byte[] ivCopy = Arrays.copyOf(iv, iv.length);
            AlgorithmParameterSpec spec;

            if (cipherType == CipherType.GCM) {
                spec = new GCMParameterSpec(128, ivCopy);
            } else {
                int blockOffset = (int) (newPosition / AES_BLOCK_SIZE_BYTES) + 2;  // Add 2 to match GCM counter block 2
                ivCopy[IV_ARRAY_LENGTH - 1] = (byte) blockOffset;
                ivCopy[IV_ARRAY_LENGTH - 2] = (byte) (blockOffset >>> 8);
                ivCopy[IV_ARRAY_LENGTH - 3] = (byte) (blockOffset >>> 16);
                ivCopy[IV_ARRAY_LENGTH - 4] = (byte) (blockOffset >>> 24);
                spec = new IvParameterSpec(ivCopy);
            }

            cipher.init(opmode, key, spec);

            // Skip over any partial block offset using dummy update (CTR only)
            if (cipherType == CipherType.CTR && newPosition % AES_BLOCK_SIZE_BYTES > 0) {
                cipher.update(ZERO_SKIP, 0, (int) (newPosition % AES_BLOCK_SIZE_BYTES));
            }
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException("Failed to initialize cipher", e);
        }
    }
}
