/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.index.store.footer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Format: [MessageId(16)][Magic(4)] = 20 bytes total
 */
public class EncryptionFooter {
    
    public static final byte[] MAGIC = "OSEF".getBytes();
    public static final int MESSAGE_ID_SIZE = 16;
    public static final int FOOTER_SIZE = MESSAGE_ID_SIZE + MAGIC.length;
    
    private final byte[] messageId;
    
    public EncryptionFooter(byte[] messageId) {
        if (messageId.length != MESSAGE_ID_SIZE) {
            throw new IllegalArgumentException("MessageId must be 16 bytes");
        }
        this.messageId = Arrays.copyOf(messageId, MESSAGE_ID_SIZE);
    }
    
    public static EncryptionFooter generateNew() {
        byte[] messageId = new byte[MESSAGE_ID_SIZE];
        new SecureRandom().nextBytes(messageId);
        return new EncryptionFooter(messageId);
    }
    
    public byte[] serialize() {
        ByteBuffer buffer = ByteBuffer.allocate(FOOTER_SIZE);
        buffer.put(messageId);
        buffer.put(MAGIC);
        return buffer.array();
    }
    
    public static EncryptionFooter deserialize(byte[] footerBytes) throws IOException {
        if (footerBytes.length != FOOTER_SIZE) {
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
    
    public byte[] getMessageId() {
        return Arrays.copyOf(messageId, MESSAGE_ID_SIZE);
    }
}