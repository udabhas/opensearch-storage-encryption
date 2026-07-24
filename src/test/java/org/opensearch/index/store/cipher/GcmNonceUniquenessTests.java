/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Validates that AesGcmCipherFactory.computeGcmNonce produces unique nonces
 * per chunk, ensuring cryptographic correctness of translog encryption.
 */
public class GcmNonceUniquenessTests extends OpenSearchTestCase {

    private static final byte[] TEST_KEY = new byte[32];
    private static final byte[] BASE_IV = new byte[16];

    static {
        Arrays.fill(TEST_KEY, (byte) 0x42);
        for (int i = 0; i < 16; i++)
            BASE_IV[i] = (byte) (i + 0xAA);
    }

    /**
     * Encrypting identical plaintext with nonces from different chunk indices
     * must produce different ciphertext.
     */
    public void testDifferentChunksProduceDifferentCiphertext() throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] plaintext = new byte[64];
        Arrays.fill(plaintext, (byte) 'A');

        byte[] ct0 = AesGcmCipherFactory
            .encryptWithTag(keySpec, AesGcmCipherFactory.computeGcmNonce(BASE_IV, 0), plaintext, plaintext.length);
        byte[] ct1 = AesGcmCipherFactory
            .encryptWithTag(keySpec, AesGcmCipherFactory.computeGcmNonce(BASE_IV, 1), plaintext, plaintext.length);
        byte[] ct2 = AesGcmCipherFactory
            .encryptWithTag(keySpec, AesGcmCipherFactory.computeGcmNonce(BASE_IV, 2), plaintext, plaintext.length);

        assertFalse("Chunk 0 vs 1 must differ", Arrays.equals(ct0, ct1));
        assertFalse("Chunk 0 vs 2 must differ", Arrays.equals(ct0, ct2));
        assertFalse("Chunk 1 vs 2 must differ", Arrays.equals(ct1, ct2));
    }

    /**
     * Verifies computeGcmNonce produces unique nonces across a range of indices
     * including boundary values.
     */
    public void testNonceUniquenessAcrossChunkRange() {
        Set<String> seen = new HashSet<>();
        int[] indices = { 0, 1, 2, 255, 256, 65535, 65536, Integer.MAX_VALUE };

        for (int idx : indices) {
            byte[] nonce = AesGcmCipherFactory.computeGcmNonce(BASE_IV, idx);
            assertEquals("Nonce must be 12 bytes", 12, nonce.length);
            assertTrue("Nonce for chunk " + idx + " must be unique", seen.add(bytesToHex(nonce)));
        }
    }

    /**
     * Encrypt-then-decrypt round-trip with production nonce derivation.
     */
    public void testEncryptDecryptRoundTripWithChunkNonce() throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] plaintext = "Sensitive translog operation data".getBytes();

        for (int chunkIndex : new int[] { 0, 1, 100, 65535 }) {
            byte[] nonce = AesGcmCipherFactory.computeGcmNonce(BASE_IV, chunkIndex);
            byte[] encrypted = AesGcmCipherFactory.encryptWithTag(keySpec, nonce, plaintext, plaintext.length);
            byte[] decrypted = AesGcmCipherFactory.decryptWithTag(keySpec, nonce, encrypted);
            assertArrayEquals("Round-trip failed for chunk " + chunkIndex, plaintext, decrypted);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
