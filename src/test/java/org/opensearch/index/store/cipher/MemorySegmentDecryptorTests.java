/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import static org.junit.Assert.assertArrayEquals;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.Before;
import org.opensearch.test.OpenSearchTestCase;

@SuppressWarnings("preview")
public class MemorySegmentDecryptorTests extends OpenSearchTestCase {

    private static final byte[] TEST_KEY = new byte[32]; // 256-bit AES key
    private static final byte[] TEST_IV = new byte[16];  // 128-bit IV
    private static final byte[] TEST_DATA = "Hello World Test Data for Encryption!".getBytes(StandardCharsets.UTF_8);

    private Arena arena;

    static {
        Arrays.fill(TEST_KEY, (byte) 0x42);
        Arrays.fill(TEST_IV, (byte) 0x24);
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        arena = Arena.ofConfined();
    }

    @After
    public void tearDown() throws Exception {
        if (arena != null) {
            arena.close();
        }
        super.tearDown();
    }

    public void testDecryptInPlaceWithArena() throws Exception {
        // Encrypt test data first
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, 0);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));
        byte[] encrypted = cipher.update(TEST_DATA);

        // Allocate memory segment and copy encrypted data
        MemorySegment segment = arena.allocate(encrypted.length);
        for (int i = 0; i < encrypted.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, encrypted[i]);
        }

        // Decrypt in place
        MemorySegmentDecryptor.decryptInPlace(arena, segment.address(), encrypted.length, TEST_KEY, TEST_IV, 0);

        // Verify decrypted data
        byte[] decrypted = new byte[TEST_DATA.length];
        for (int i = 0; i < decrypted.length; i++) {
            decrypted[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }

        assertArrayEquals(TEST_DATA, decrypted);
    }

    public void testDecryptInPlaceWithGlobalScope() throws Exception {
        // Encrypt test data first
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, 0);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));
        byte[] encrypted = cipher.update(TEST_DATA);

        // Allocate memory segment and copy encrypted data
        MemorySegment segment = arena.allocate(encrypted.length);
        for (int i = 0; i < encrypted.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, encrypted[i]);
        }

        // Decrypt in place using global scope
        MemorySegmentDecryptor.decryptInPlace(segment.address(), encrypted.length, TEST_KEY, TEST_IV, 0);

        // Verify decrypted data
        byte[] decrypted = new byte[TEST_DATA.length];
        for (int i = 0; i < decrypted.length; i++) {
            decrypted[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }

        assertArrayEquals(TEST_DATA, decrypted);
    }

    public void testDecryptSegment() throws Exception {
        // Encrypt test data first
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, 0);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));
        byte[] encrypted = cipher.update(TEST_DATA);

        // Allocate memory segment and copy encrypted data
        MemorySegment segment = arena.allocate(encrypted.length);
        for (int i = 0; i < encrypted.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, encrypted[i]);
        }

        // Decrypt segment
        MemorySegmentDecryptor.decryptSegment(segment, 0, TEST_KEY, TEST_IV, encrypted.length);

        // Verify decrypted data
        byte[] decrypted = new byte[TEST_DATA.length];
        for (int i = 0; i < decrypted.length; i++) {
            decrypted[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }

        assertArrayEquals(TEST_DATA, decrypted);
    }

    public void testDecryptWithFileOffset() throws Exception {
        long fileOffset = 1024;

        // Encrypt test data with offset-aware IV
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, fileOffset);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));

        // Advance cipher for non-aligned offset
        if (fileOffset % (1 << AesCipherFactory.AES_BLOCK_SIZE_BYTES_IN_POWER) > 0) {
            byte[] skip = new byte[(int) (fileOffset % (1 << AesCipherFactory.AES_BLOCK_SIZE_BYTES_IN_POWER))];
            cipher.update(skip);
        }

        byte[] encrypted = cipher.update(TEST_DATA);

        // Allocate memory segment and copy encrypted data
        MemorySegment segment = arena.allocate(encrypted.length);
        for (int i = 0; i < encrypted.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, encrypted[i]);
        }

        // Decrypt with file offset
        MemorySegmentDecryptor.decryptInPlace(arena, segment.address(), encrypted.length, TEST_KEY, TEST_IV, fileOffset);

        // Verify decrypted data
        byte[] decrypted = new byte[TEST_DATA.length];
        for (int i = 0; i < decrypted.length; i++) {
            decrypted[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }

        assertArrayEquals(TEST_DATA, decrypted);
    }

    public void testDecryptLargeData() throws Exception {
        // Test with data larger than default chunk size
        byte[] largeData = new byte[32768]; // 32KB
        new SecureRandom().nextBytes(largeData);

        // Encrypt
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, 0);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));
        byte[] encrypted = cipher.doFinal(largeData);

        // Allocate memory segment and copy encrypted data
        MemorySegment segment = arena.allocate(encrypted.length);
        for (int i = 0; i < encrypted.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, encrypted[i]);
        }

        // Decrypt
        MemorySegmentDecryptor.decryptInPlace(arena, segment.address(), encrypted.length, TEST_KEY, TEST_IV, 0);

        // Verify
        byte[] decrypted = new byte[largeData.length];
        for (int i = 0; i < decrypted.length; i++) {
            decrypted[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }

        assertArrayEquals(largeData, decrypted);
    }

    public void testDecryptWithNonAlignedOffset() throws Exception {
        long fileOffset = 17; // Non-aligned offset

        // Encrypt with offset
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, fileOffset);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));

        // Advance cipher for non-aligned offset
        int skipBytes = (int) (fileOffset % (1 << AesCipherFactory.AES_BLOCK_SIZE_BYTES_IN_POWER));
        if (skipBytes > 0) {
            cipher.update(new byte[skipBytes]);
        }

        byte[] encrypted = cipher.update(TEST_DATA);

        // Allocate and decrypt
        MemorySegment segment = arena.allocate(encrypted.length);
        for (int i = 0; i < encrypted.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, encrypted[i]);
        }

        MemorySegmentDecryptor.decryptInPlace(arena, segment.address(), encrypted.length, TEST_KEY, TEST_IV, fileOffset);

        // Verify
        byte[] decrypted = new byte[TEST_DATA.length];
        for (int i = 0; i < decrypted.length; i++) {
            decrypted[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }

        assertArrayEquals(TEST_DATA, decrypted);
    }

    public void testDecryptEmptyData() throws Exception {
        byte[] emptyData = new byte[0];

        // Encrypt empty data
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, 0);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));
        byte[] encrypted = cipher.update(emptyData);

        if (encrypted == null || encrypted.length == 0) {
            // Empty encryption is valid
            return;
        }

        // Allocate and decrypt
        MemorySegment segment = arena.allocate(Math.max(1, encrypted.length));
        MemorySegmentDecryptor.decryptInPlace(arena, segment.address(), encrypted.length, TEST_KEY, TEST_IV, 0);

        // Should complete without error
    }

    public void testDecryptMultipleSegments() throws Exception {
        int segmentCount = 5;
        byte[][] originalData = new byte[segmentCount][];
        MemorySegment[] segments = new MemorySegment[segmentCount];

        for (int i = 0; i < segmentCount; i++) {
            originalData[i] = ("Segment " + i + " data content").getBytes(StandardCharsets.UTF_8);

            // Encrypt
            Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
            SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
            byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, i * 1024L);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));

            if ((i * 1024L) % (1 << AesCipherFactory.AES_BLOCK_SIZE_BYTES_IN_POWER) > 0) {
                cipher.update(new byte[(int) ((i * 1024L) % (1 << AesCipherFactory.AES_BLOCK_SIZE_BYTES_IN_POWER))]);
            }

            byte[] encrypted = cipher.update(originalData[i]);

            // Allocate segment
            segments[i] = arena.allocate(encrypted.length);
            for (int j = 0; j < encrypted.length; j++) {
                segments[i].set(ValueLayout.JAVA_BYTE, j, encrypted[j]);
            }

            // Decrypt
            MemorySegmentDecryptor.decryptSegment(segments[i], i * 1024L, TEST_KEY, TEST_IV, encrypted.length);

            // Verify
            byte[] decrypted = new byte[originalData[i].length];
            for (int j = 0; j < decrypted.length; j++) {
                decrypted[j] = segments[i].get(ValueLayout.JAVA_BYTE, j);
            }

            assertArrayEquals("Segment " + i + " mismatch", originalData[i], decrypted);
        }
    }

    /**
     * Regression test: the multi-frame SLOW path of {@link MemorySegmentDecryptor#decryptInPlaceFrameBased}
     * must decrypt each frame with a WITHIN-FRAME CTR counter, matching the write path (which re-initializes a fresh
     * cipher at each frame boundary). The bug passed the ABSOLUTE file offset to {@code decryptInPlace}, so for any
     * frame N&gt;=1 the counter was wrong and the plaintext came back garbage. This test lays out ciphertext that
     * straddles a frame boundary (built per-frame the way the write path emits it) and asserts a clean round-trip.
     *
     * <p>Uses a small synthetic frame size to make the multi-frame path reachable without a 32GB buffer.
     */
    public void testDecryptInPlaceFrameBasedMultiFrameBoundary() throws Exception {
        final long frameSize = 256;                 // small frame so the multi-frame slow path is reachable
        final byte[] messageId = new byte[16];
        Arrays.fill(messageId, (byte) 0x07);
        final byte[] fileKey = new byte[32];
        Arrays.fill(fileKey, (byte) 0x11);
        final byte[] directoryKey = TEST_KEY;       // used only for frame-IV derivation
        final String path = "/tmp/p1_3_boundary.bin";
        final EncryptionMetadataCache cache = new EncryptionMetadataCache();

        // Read window straddles frame 0 -> frame 1, with a non-block-aligned start (exercises ZERO_SKIP too).
        final long fileOffset = 250;                // frame 0: [250,256) = 6 bytes; frame 1: [256,270) = 14 bytes
        final int length = 20;

        byte[] plaintext = new byte[length];
        for (int i = 0; i < length; i++) {
            plaintext[i] = (byte) (i + 1);
        }

        MemorySegment seg = arena.allocate(length);
        MemorySegment.copy(plaintext, 0, seg, ValueLayout.JAVA_BYTE, 0, length);

        // Build the ciphertext the way the write path does: each frame is encrypted by a cipher (re)started at
        // that frame, i.e. keyed on the WITHIN-FRAME offset. AES-CTR is symmetric, so applying decryptInPlace with
        // the correct per-frame within-frame offset turns the plaintext into the on-disk ciphertext.
        int frame0Len = (int) (frameSize - (fileOffset % frameSize));   // 6
        byte[] iv0 = AesCipherFactory.computeFrameIV(directoryKey, messageId, 0, fileOffset % frameSize, path, cache);
        MemorySegmentDecryptor.decryptInPlace(seg.address(), frame0Len, fileKey, iv0, fileOffset % frameSize);
        byte[] iv1 = AesCipherFactory.computeFrameIV(directoryKey, messageId, 1, 0, path, cache);
        MemorySegmentDecryptor.decryptInPlace(seg.address() + frame0Len, length - frame0Len, fileKey, iv1, 0);

        // Decrypt via the production multi-frame path. Pre-fix, frame 1 decrypts with counter (256>>4)+2 instead of
        // (0>>4)+2 -> garbage; post-fix it uses the within-frame offset and round-trips.
        MemorySegmentDecryptor
            .decryptInPlaceFrameBased(seg.address(), length, fileKey, directoryKey, messageId, frameSize, fileOffset, path, cache);

        byte[] result = new byte[length];
        MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, 0, result, 0, length);
        assertArrayEquals("multi-frame boundary decrypt must round-trip", plaintext, result);
    }

    /**
     * Regression test spanning FOUR frames (0,1,2,3) so the fix is exercised for several N&gt;=1 frames in a
     * single call, not just the first boundary.
     */
    public void testDecryptInPlaceFrameBasedSpansManyFrames() throws Exception {
        final long frameSize = 256;
        final byte[] messageId = new byte[16];
        Arrays.fill(messageId, (byte) 0x5A);
        final byte[] fileKey = new byte[32];
        Arrays.fill(fileKey, (byte) 0x33);
        final byte[] directoryKey = TEST_KEY;
        final String path = "/tmp/p1_3_manyframes.bin";
        final EncryptionMetadataCache cache = new EncryptionMetadataCache();

        final long fileOffset = 250;                // starts near end of frame 0
        final int length = 600;                     // spans frames 0,1,2,3

        byte[] plaintext = new byte[length];
        new SecureRandom().nextBytes(plaintext);

        MemorySegment seg = arena.allocate(length);
        MemorySegment.copy(plaintext, 0, seg, ValueLayout.JAVA_BYTE, 0, length);

        // Emit ciphertext frame-by-frame using within-frame offsets (models the write path).
        long remaining = length;
        long currentOffset = fileOffset;
        long bufferOffset = 0;
        while (remaining > 0) {
            long frameNumber = currentOffset / frameSize;
            long frameStart = frameNumber * frameSize;
            long frameEnd = frameStart + frameSize;
            long bytesInFrame = Math.min(remaining, frameEnd - currentOffset);
            long offsetWithinFrame = currentOffset - frameStart;

            byte[] iv = AesCipherFactory.computeFrameIV(directoryKey, messageId, frameNumber, offsetWithinFrame, path, cache);
            MemorySegmentDecryptor.decryptInPlace(seg.address() + bufferOffset, bytesInFrame, fileKey, iv, offsetWithinFrame);

            currentOffset += bytesInFrame;
            bufferOffset += bytesInFrame;
            remaining -= bytesInFrame;
        }

        MemorySegmentDecryptor
            .decryptInPlaceFrameBased(seg.address(), length, fileKey, directoryKey, messageId, frameSize, fileOffset, path, cache);

        byte[] result = new byte[length];
        MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, 0, result, 0, length);
        assertArrayEquals("multi-frame span decrypt must round-trip across frames 0-3", plaintext, result);
    }

    public void testChunkedDecryption() throws Exception {
        // Test that chunked processing works correctly
        int dataSize = 20000; // Larger than default chunk size
        byte[] testData = new byte[dataSize];
        new SecureRandom().nextBytes(testData);

        // Encrypt
        Cipher cipher = AesCipherFactory.CIPHER_POOL.get();
        SecretKeySpec keySpec = new SecretKeySpec(TEST_KEY, "AES");
        byte[] offsetIV = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(TEST_IV, 0);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(offsetIV));
        byte[] encrypted = cipher.doFinal(testData);

        // Allocate segment
        MemorySegment segment = arena.allocate(encrypted.length);
        for (int i = 0; i < encrypted.length; i++) {
            segment.set(ValueLayout.JAVA_BYTE, i, encrypted[i]);
        }

        // Decrypt using chunked processing
        MemorySegmentDecryptor.decryptSegment(segment, 0, TEST_KEY, TEST_IV, encrypted.length);

        // Verify
        byte[] decrypted = new byte[testData.length];
        for (int i = 0; i < decrypted.length; i++) {
            decrypted[i] = segment.get(ValueLayout.JAVA_BYTE, i);
        }

        assertArrayEquals(testData, decrypted);
    }
}
