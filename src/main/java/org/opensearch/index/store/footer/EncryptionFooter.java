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
 * Format: [GcmTags...][TagsLength(4)][MessageId(16)][FooterLength(4)][Magic(4)]
 * 
 * Frame Support: Files are encrypted in frames to support large files (>64GB)
 * and enable random access without decrypting entire file.
 */
public class EncryptionFooter {
    
    public static final byte[] MAGIC = "OSEF".getBytes();
    public static final int MESSAGE_ID_SIZE = 16;
    public static final int FOOTER_LENGTH_SIZE = 4;
    public static final int TAGS_LENGTH_SIZE = 4;
    public static final int FIXED_FOOTER_SIZE = MESSAGE_ID_SIZE + FOOTER_LENGTH_SIZE + MAGIC.length; // 24 bytes
    public static final int MIN_FOOTER_SIZE = FIXED_FOOTER_SIZE + TAGS_LENGTH_SIZE; // 28 bytes

    // Frame constants for large file support
    public static final long DEFAULT_FRAME_SIZE = 64L * 1024 * 1024 * 1024; // 64GB per frame
    public static final int MAX_FRAMES_PER_FILE = Integer.MAX_VALUE; // Support very large files
    public static final String FRAME_CONTEXT_PREFIX = "frame-"; // Context for frame key derivation
    
    private final byte[] messageId;
    private final List<byte[]> gcmTagsList;

    public EncryptionFooter(byte[] messageId) {
        if (messageId.length != MESSAGE_ID_SIZE) {
            throw new IllegalArgumentException("MessageId must be 16 bytes");
        }
        this.messageId = Arrays.copyOf(messageId, MESSAGE_ID_SIZE);
        gcmTagsList = new ArrayList<byte[]>();
    }
    
    public static EncryptionFooter generateNew() {
        byte[] messageId = new byte[MESSAGE_ID_SIZE];
        new SecureRandom().nextBytes(messageId);
        return new EncryptionFooter(messageId);
    }
    
    public byte[] serialize() {
        int footerSize = FIXED_FOOTER_SIZE + TAGS_LENGTH_SIZE + 
                (gcmTagsList.size() * AesGcmCipherFactory.GCM_TAG_LENGTH);

        ByteBuffer buffer = ByteBuffer.allocate(footerSize);

        // Write GCM tags
        for(byte[] tag : gcmTagsList) {
            buffer.put(tag);
        }
        
        // Write tags count
        buffer.putInt(gcmTagsList.size());
        
        // Write message ID
        buffer.put(messageId);
        
        // Write footer length
        buffer.putInt(footerSize);
        
        // Write magic
        buffer.put(MAGIC);

        return buffer.array();
    }
    
    public static EncryptionFooter deserialize(byte[] footerBytes) throws IOException {
        if (footerBytes.length != 20) {
            throw new IOException("Invalid footer size: " + footerBytes.length);
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(footerBytes);
        
        // Read MessageId
        byte[] messageId = new byte[MESSAGE_ID_SIZE];
        buffer.get(messageId);
        
        // Verify magic
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Invalid footer magic");
        }
        
        return new EncryptionFooter(messageId);
    }

    public static EncryptionFooter deserialize2(byte[] fileBytes) throws IOException {
        if (fileBytes.length < MIN_FOOTER_SIZE) {
            throw new IOException("Invalid footer size: " + fileBytes.length);
        }

        // Read from END: [TagsLength(4)][MessageId(16)][FooterLength(4)][Magic(4)]
        int magicPos = fileBytes.length - MAGIC.length;
        int footerLengthPos = magicPos - FOOTER_LENGTH_SIZE;
        int messageIdPos = footerLengthPos - MESSAGE_ID_SIZE;
        int tagsLengthPos = messageIdPos - TAGS_LENGTH_SIZE;

        // Verify magic
        byte[] magic = new byte[MAGIC.length];
        System.arraycopy(fileBytes, magicPos, magic, 0, MAGIC.length);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Invalid footer magic");
        }
        
        // Read footer length
        int footerLength = ByteBuffer.wrap(fileBytes, footerLengthPos, FOOTER_LENGTH_SIZE).getInt();
        
        // Read MessageId
        byte[] messageId = new byte[MESSAGE_ID_SIZE];
        System.arraycopy(fileBytes, messageIdPos, messageId, 0, MESSAGE_ID_SIZE);

        // Read tags count
        int gcmTagsLength = ByteBuffer.wrap(fileBytes, tagsLengthPos, TAGS_LENGTH_SIZE).getInt();

        // Validate footer length
        int expectedFooterLength = FIXED_FOOTER_SIZE + TAGS_LENGTH_SIZE + 
                (gcmTagsLength * AesGcmCipherFactory.GCM_TAG_LENGTH);
        if (footerLength != expectedFooterLength) {
            throw new IOException("Footer length mismatch: expected " + expectedFooterLength + 
                    ", got " + footerLength);
        }

        // Create footer and read GCM tags
        EncryptionFooter footer = new EncryptionFooter(messageId);
        
        // Calculate start position of GCM tags
        int tagsStartPos = fileBytes.length - footerLength;
        
        // Read tags in order
        for(int i = 0; i < gcmTagsLength; i++) {
            byte[] tag = new byte[AesGcmCipherFactory.GCM_TAG_LENGTH];
            int tagOffset = tagsStartPos + (i * AesGcmCipherFactory.GCM_TAG_LENGTH);
            System.arraycopy(fileBytes, tagOffset, tag, 0, AesGcmCipherFactory.GCM_TAG_LENGTH);
            footer.addGcmTagToFooter(tag);
        }

        return footer;
    }

    public static int calculateFooterLength(byte[] fileBytes) throws IOException {
        if (fileBytes.length < MIN_FOOTER_SIZE) {
            throw new IOException("Invalid footer size: " + fileBytes.length);
        }

        // Read from END: [FooterLength(4)][Magic(4)]
        int magicPos = fileBytes.length - MAGIC.length;
        int footerLengthPos = magicPos - FOOTER_LENGTH_SIZE;

        // Verify magic
        byte[] magic = new byte[MAGIC.length];
        System.arraycopy(fileBytes, magicPos, magic, 0, MAGIC.length);
        if (!Arrays.equals(magic, MAGIC)) {
            throw new IOException("Invalid footer magic");
        }

        // Read and return footer length directly
        return ByteBuffer.wrap(fileBytes, footerLengthPos, FOOTER_LENGTH_SIZE).getInt();
    }
    
    public byte[] getMessageId() {
        return Arrays.copyOf(messageId, MESSAGE_ID_SIZE);
    }

    public void addGcmTagToFooter(byte[] tag) throws IOException {
        if(tag.length != AesGcmCipherFactory.GCM_TAG_LENGTH) {
            throw new IOException("Invalid Tag Length" + tag.length);
        }
        gcmTagsList.add(tag);
    }
}