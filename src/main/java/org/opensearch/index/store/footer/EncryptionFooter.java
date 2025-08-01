/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.index.store.footer;

import org.opensearch.index.store.cipher.AesGcmCipherFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Footer format: [GcmTags...][TagCount(4)][FrameSize(8)][FrameCount(4)][MessageId(16)][KeyMetadata(0)][KeyMetadataLength(2)][AlgorithmId(2)][FooterLength(4)][Magic(4)]
 */
public class EncryptionFooter {
    
    public static final byte[] MAGIC = "OSEF".getBytes();
    public static final int MESSAGE_ID_SIZE = 16;
    public static final int TAG_COUNT_SIZE = 4;
    public static final int FRAME_SIZE_SIZE = 8;
    public static final int FRAME_COUNT_SIZE = 4;
    public static final int KEY_METADATA_LENGTH_SIZE = 2; // Currently unused - key data from ivFile/keyfile
    public static final int ALGORITHM_ID_SIZE = 2;
    public static final int FOOTER_LENGTH_SIZE = 4;
    public static final int FIXED_FOOTER_SIZE = MESSAGE_ID_SIZE + KEY_METADATA_LENGTH_SIZE + ALGORITHM_ID_SIZE + FOOTER_LENGTH_SIZE + MAGIC.length; // 28 bytes
    public static final int MIN_FOOTER_SIZE = FIXED_FOOTER_SIZE + TAG_COUNT_SIZE + FRAME_SIZE_SIZE + FRAME_COUNT_SIZE; // 44 bytes
    
    // Frame constants for large file support
    public static final long DEFAULT_FRAME_SIZE = 64L * 1024 * 1024 * 1024; // 64GB per frame
    public static final int MAX_FRAMES_PER_FILE = Integer.MAX_VALUE; // Support very large files
    public static final String FRAME_CONTEXT_PREFIX = "frame-"; // Context for frame key derivation
    
    private final byte[] messageId;
    private final List<byte[]> gcmTags;
    private final long frameSize;
    private final short algorithmId;
    private final byte[] keyMetadata; // Currently empty - key data retrieved from ivFile/keyfile
    private int frameCount;
    
    public EncryptionFooter(byte[] messageId, long frameSize, short algorithmId) {
        if (messageId.length != MESSAGE_ID_SIZE) {
            throw new IllegalArgumentException("MessageId must be 16 bytes");
        }
        this.messageId = Arrays.copyOf(messageId, MESSAGE_ID_SIZE);
        this.gcmTags = new ArrayList<>();
        this.frameSize = frameSize;
        this.algorithmId = algorithmId;
        this.keyMetadata = new byte[0]; // Empty - currently using ivFile/keyfile for key data
        this.frameCount = 0;
    }
    
    public static EncryptionFooter generateNew(long frameSize, short algorithmId) {
        byte[] messageId = new byte[MESSAGE_ID_SIZE];
        new SecureRandom().nextBytes(messageId);
        return new EncryptionFooter(messageId, frameSize, algorithmId);
    }


    public byte[] serialize() {
        int footerSize = MIN_FOOTER_SIZE + (gcmTags.size() * AesGcmCipherFactory.GCM_TAG_LENGTH) + keyMetadata.length;
        ByteBuffer buffer = ByteBuffer.allocate(footerSize);
        
        // Write GCM tags
        for (byte[] tag : gcmTags) {
            buffer.put(tag);
        }
        
        // Write tag count
        buffer.putInt(gcmTags.size());
        
        // Write frame size
        buffer.putLong(frameSize);
        
        // Write frame count
        buffer.putInt(frameCount);
        
        // Write MessageId
        buffer.put(messageId);
        
        // Write KeyMetadata (empty - using ivFile/keyfile)
        buffer.put(keyMetadata);
        
        // Write KeyMetadataLength
        buffer.putShort((short) keyMetadata.length);
        
        // Write algorithm ID
        buffer.putShort(algorithmId);
        
        // Write footer length
        buffer.putInt(footerSize);
        
        // Write magic
        buffer.put(MAGIC);
        
        return buffer.array();
    }
    
    public static EncryptionFooter deserialize(byte[] fileBytes) throws IOException {
        if (fileBytes.length < MIN_FOOTER_SIZE) {
            throw new IOException("Invalid footer size: " + fileBytes.length);
        }
        
        int pos = fileBytes.length;
        
        // Read magic
        pos -= MAGIC.length;
        byte[] magic = Arrays.copyOfRange(fileBytes, pos, pos + MAGIC.length);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Invalid footer magic");
        }
        
        // Read footer length
        pos -= FOOTER_LENGTH_SIZE;
        int footerLength = ByteBuffer.wrap(fileBytes, pos, FOOTER_LENGTH_SIZE).getInt();
        
        // Read algorithm ID
        pos -= ALGORITHM_ID_SIZE;
        short algorithmId = ByteBuffer.wrap(fileBytes, pos, ALGORITHM_ID_SIZE).getShort();
        
        // Read KeyMetadataLength
        pos -= KEY_METADATA_LENGTH_SIZE;
        short keyMetadataLength = ByteBuffer.wrap(fileBytes, pos, KEY_METADATA_LENGTH_SIZE).getShort();
        
        // Read KeyMetadata (currently empty)
        pos -= keyMetadataLength;
        byte[] keyMetadata = Arrays.copyOfRange(fileBytes, pos, pos + keyMetadataLength);
        
        // Read MessageId
        pos -= MESSAGE_ID_SIZE;
        byte[] messageId = Arrays.copyOfRange(fileBytes, pos, pos + MESSAGE_ID_SIZE);
        
        // Read frame count
        pos -= FRAME_COUNT_SIZE;
        int frameCount = ByteBuffer.wrap(fileBytes, pos, FRAME_COUNT_SIZE).getInt();
        
        // Read frame size
        pos -= FRAME_SIZE_SIZE;
        long frameSize = ByteBuffer.wrap(fileBytes, pos, FRAME_SIZE_SIZE).getLong();
        
        // Read tag count
        pos -= TAG_COUNT_SIZE;
        int tagCount = ByteBuffer.wrap(fileBytes, pos, TAG_COUNT_SIZE).getInt();
        
        // Validate footer length
        int expectedLength = MIN_FOOTER_SIZE + (tagCount * AesGcmCipherFactory.GCM_TAG_LENGTH) + keyMetadataLength;
        if (footerLength != expectedLength) {
            throw new IOException("Footer length mismatch: expected " + expectedLength + ", got " + footerLength);
        }
        
        // Create footer and read GCM tags
        EncryptionFooter footer = new EncryptionFooter(messageId, frameSize, algorithmId);
        footer.frameCount = frameCount;
        int tagStartPos = fileBytes.length - footerLength;
        
        for (int i = 0; i < tagCount; i++) {
            int tagPos = tagStartPos + (i * AesGcmCipherFactory.GCM_TAG_LENGTH);
            byte[] tag = Arrays.copyOfRange(fileBytes, tagPos, tagPos + AesGcmCipherFactory.GCM_TAG_LENGTH);
            footer.addGcmTag(tag);
        }
        
        return footer;
    }
    
    public static int calculateFooterLength(byte[] footerBytes) throws IOException {
        if (footerBytes.length < MIN_FOOTER_SIZE) {
            throw new IOException("Footer too small: " + footerBytes.length);
        }
        
        // Read footer length from end: [FooterLength(4)][Magic(4)]
        int pos = footerBytes.length - MAGIC.length - FOOTER_LENGTH_SIZE;
        return ByteBuffer.wrap(footerBytes, pos, FOOTER_LENGTH_SIZE).getInt();
    }
    
    public byte[] getMessageId() {
        return Arrays.copyOf(messageId, MESSAGE_ID_SIZE);
    }
    
    public void addGcmTag(byte[] tag) throws IOException {
        if (tag.length != AesGcmCipherFactory.GCM_TAG_LENGTH) {
            throw new IOException("Invalid GCM tag length: " + tag.length);
        }
        gcmTags.add(Arrays.copyOf(tag, tag.length));
    }
    
    public long getFrameSize() {
        return frameSize;
    }
    
    public int getFrameCount() {
        return frameCount;
    }
    
    public void setFrameCount(int frameCount) {
        this.frameCount = frameCount;
    }
    
    public short getAlgorithmId() {
        return algorithmId;
    }
    
    public byte[] getKeyMetadata() {
        return Arrays.copyOf(keyMetadata, keyMetadata.length);
    }
}