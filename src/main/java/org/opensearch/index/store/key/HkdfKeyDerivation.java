/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF (HMAC-based Key Derivation Function) implementation for deriving keys from MessageId.
 * Based on RFC 5869: https://tools.ietf.org/html/rfc5869
 *
 * <p>Translog base-IV overloads (use the most specific one available): {@code (key,uuid,gen,epoch,salt)} is
 * the current FRAME-AAD derivation; the shorter overloads are legacy/fallbacks for files written before
 * generation/epoch/salt were folded in.
 *
 * @opensearch.internal
 */
public class HkdfKeyDerivation {

    private static final String HMAC_ALGORITHM = "HmacSHA384";
    private static final int HASH_LENGTH = 48; // SHA-384 output length

    /**
     * Derive a file key from Master Key + MessageId using HKDF
     *
     * @param masterKey the master key (32 bytes)
     * @param messageId the unique file identifier (16 bytes from footer)
     * @param context the context string for key derivation
     * @param keyLength the desired output key length in bytes
     * @return derived key bytes
     */
    public static byte[] deriveKey(byte[] masterKey, byte[] messageId, String context, int keyLength) {
        if (masterKey == null || masterKey.length != 32) {
            throw new IllegalArgumentException("Master key must be 32 bytes");
        }
        if (messageId == null || messageId.length != 16) {
            throw new IllegalArgumentException("MessageId must be 16 bytes");
        }
        if (keyLength <= 0 || keyLength > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("Invalid key length: " + keyLength);
        }

        try {
            // HKDF-Extract: PRK = HMAC-Hash(masterKey, messageId)
            // Use master key as salt, messageId as input key material
            byte[] prk = hmac(masterKey, messageId);

            // HKDF-Expand: OKM = HMAC-Hash(PRK, info || counter)
            byte[] info = context.getBytes(StandardCharsets.UTF_8);
            return hkdfExpand(prk, info, keyLength);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HKDF key derivation failed", e);
        }
    }

    /**
     * Convenience method for deriving AES-256 file keys (32 bytes)
     */
    public static byte[] deriveAesKey(byte[] masterKey, byte[] messageId, String context) {
        return deriveKey(masterKey, messageId, context, 32);
    }

    private static byte[] hmac(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return mac.doFinal(data);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        int n = (length + HASH_LENGTH - 1) / HASH_LENGTH; // Ceiling division
        byte[] okm = new byte[length];
        byte[] t = new byte[0];

        for (int i = 1; i <= n; i++) {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(prk, HMAC_ALGORITHM));
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();

            int copyLength = Math.min(HASH_LENGTH, length - (i - 1) * HASH_LENGTH);
            System.arraycopy(t, 0, okm, (i - 1) * HASH_LENGTH, copyLength);
        }

        return okm;
    }

    /**
     * Derive file key directly from master key and messageId.
     *
     * @param masterKey the master key (32 bytes)
     * @param messageId the file's unique message ID (16 bytes)
     * @return derived 32-byte file key
     */
    public static byte[] deriveFileKey(byte[] masterKey, byte[] messageId) {
        return deriveKey(masterKey, messageId, "file-encryption", 32);
    }

    /**
     * Derive base IV for translog encryption from master key and translog UUID.
     * This ensures deterministic IV generation for translog files.
     *
     * @param masterKey the master key (32 bytes)
     * @param translogUUID the translog UUID string
     * @return derived 16-byte base IV for translog
     */
    public static byte[] deriveTranslogBaseIV(byte[] masterKey, String translogUUID) {
        byte[] uuidBytes = translogUUID.getBytes(StandardCharsets.UTF_8);
        byte[] paddedUuid = new byte[16];
        System.arraycopy(uuidBytes, 0, paddedUuid, 0, Math.min(uuidBytes.length, 16));
        return deriveKey(masterKey, paddedUuid, "translog-base-iv", 16);
    }

    /**
     * Derive a per-generation base IV. Folding the generation into the context gives each generation file a
     * distinct base IV, avoiding (key, nonce) reuse on block 0 across files. Reconstructable from the
     * {@code translog-N.tlog} filename at read time.
     *
     * @param masterKey the master key (32 bytes)
     * @param translogUUID the translog UUID string
     * @param generation the translog generation number (from the {@code translog-N.tlog} filename)
     * @return derived 16-byte base IV for this generation
     */
    public static byte[] deriveTranslogBaseIV(byte[] masterKey, String translogUUID, long generation) {
        byte[] uuidBytes = translogUUID.getBytes(StandardCharsets.UTF_8);
        byte[] paddedUuid = new byte[16];
        System.arraycopy(uuidBytes, 0, paddedUuid, 0, Math.min(uuidBytes.length, 16));
        return deriveKey(masterKey, paddedUuid, "translog-base-iv|gen=" + generation, 16);
    }

    /**
     * Derive a per-(generation, key-epoch) base IV. The epoch additionally makes the base IV unique across
     * key rotations, so frame 0 under a new epoch cannot collide with the old epoch. Both inputs are on disk
     * (filename + super-header), so it is reconstructable at read time.
     *
     * @param masterKey the master key (32 bytes) for the given epoch
     * @param translogUUID the translog UUID string
     * @param generation the translog generation number (from the {@code translog-N.tlog} filename)
     * @param keyEpoch the key-rotation epoch for this file (from the super-header)
     * @return derived 16-byte base IV for this (generation, epoch)
     */
    public static byte[] deriveTranslogBaseIV(byte[] masterKey, String translogUUID, long generation, int keyEpoch) {
        byte[] uuidBytes = translogUUID.getBytes(StandardCharsets.UTF_8);
        byte[] paddedUuid = new byte[16];
        System.arraycopy(uuidBytes, 0, paddedUuid, 0, Math.min(uuidBytes.length, 16));
        return deriveKey(masterKey, paddedUuid, "translog-base-iv|gen=" + generation + "|epoch=" + keyEpoch, 16);
    }

    /**
     * Derive a per-(generation, key-epoch, file-salt) base IV. The random per-file salt fixes cross-file
     * nonce reuse: {@code (generation, epoch)} alone are not unique across two physical files of the same
     * generation (e.g. the original primary file vs. a remote-store restore that re-encrypts the same
     * generation from plaintext) — both would otherwise reuse {@code baseIV[0:8]||BE32(0)} on distinct
     * frame-0 plaintexts. The salt is generated once, persisted in the super-header, and read back on open.
     *
     * @param masterKey the master key (32 bytes) for the given epoch
     * @param translogUUID the translog UUID string
     * @param generation the translog generation number (from the {@code translog-N.tlog} filename)
     * @param keyEpoch the key-rotation epoch for this file (from the super-header)
     * @param fileSalt the per-file random salt (persisted in the super-header reserved field)
     * @return derived 16-byte base IV for this (generation, epoch, salt)
     */
    public static byte[] deriveTranslogBaseIV(byte[] masterKey, String translogUUID, long generation, int keyEpoch, long fileSalt) {
        byte[] uuidBytes = translogUUID.getBytes(StandardCharsets.UTF_8);
        byte[] paddedUuid = new byte[16];
        System.arraycopy(uuidBytes, 0, paddedUuid, 0, Math.min(uuidBytes.length, 16));
        return deriveKey(masterKey, paddedUuid, "translog-base-iv|gen=" + generation + "|epoch=" + keyEpoch + "|salt=" + fileSalt, 16);
    }
}
