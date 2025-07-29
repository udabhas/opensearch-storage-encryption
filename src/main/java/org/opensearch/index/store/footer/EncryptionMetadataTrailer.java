/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.index.store.footer;

import java.nio.charset.StandardCharsets;

/**
 * Constants and utilities for encryption metadata footer format.
 * 
 * Footer format (read backwards from end of file):
 * [FooterAuthTag][GCMTagList][FrameCount][FrameSize][MessageId][KeyMetadata][KeyMetadataLength][AlgorithmId][FooterLength][MagicBytes]
 * 
 * Features:
 * - Frame-based encryption to overcome GCM 64GB limit
 * - HKDF key derivation using MessageId
 * - Footer authentication to prevent tampering
 * - Algorithm agility for future evolution
 * - Variable KeyMetadata for different key providers
 * 
 * @opensearch.internal
 */
public class EncryptionMetadataTrailer {

    // Magic bytes at the very end for reliable footer detection
    public static final String ENCRYPTION_MAGIC_STRING = "OSEF"; // OpenSearch Encrypted File
    public static final byte[] ENCRYPTION_MAGIC_BYTES = ENCRYPTION_MAGIC_STRING.getBytes(StandardCharsets.UTF_8);
    
    // Field sizes in bytes
    public static final int MAGIC_BYTES_SIZE = 4;
    public static final int FOOTER_LENGTH_SIZE = 2;
    public static final int ALGORITHM_ID_SIZE = 2;
    public static final int KEY_METADATA_LENGTH_SIZE = 2;
    public static final int MESSAGE_ID_SIZE = 16;
    public static final int FRAME_SIZE_SIZE = 6; // Supports up to 256TB frames
    public static final int FRAME_COUNT_SIZE = 2;
    public static final int GCM_TAG_SIZE = 16;
    public static final int FOOTER_AUTH_TAG_SIZE = 16;
    
    // Minimum footer size (without variable parts)
    public static final int MIN_FOOTER_SIZE = MAGIC_BYTES_SIZE + FOOTER_LENGTH_SIZE + 
                                             ALGORITHM_ID_SIZE + KEY_METADATA_LENGTH_SIZE + 
                                             MESSAGE_ID_SIZE + FRAME_SIZE_SIZE + 
                                             FRAME_COUNT_SIZE + FOOTER_AUTH_TAG_SIZE;
    
    // Algorithm IDs for future extensibility
    public static final int ALGORITHM_AES_256_GCM = 1;
    
    // Special IV for footer authentication (won't collide with frame IVs)
    public static final byte[] FOOTER_AUTH_IV = new byte[]{
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
    };
    
    /**
     * Calculate total footer size including variable parts
     * @param frameCount number of frames in the file
     * @param keyMetadataLength length of key metadata
     * @return total footer size in bytes
     */
    public static int calculateFooterSize(int frameCount, int keyMetadataLength) {
        return MIN_FOOTER_SIZE + (frameCount * GCM_TAG_SIZE) + keyMetadataLength;
    }
}