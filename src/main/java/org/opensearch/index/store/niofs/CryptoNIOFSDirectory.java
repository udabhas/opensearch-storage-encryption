/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.apache.lucene.store.NIOFSDirectory;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * A NioFS directory implementation that encrypts files to be stored based on a
 * user supplied key
 *
 * @opensearch.internal
 */
public class CryptoNIOFSDirectory extends NIOFSDirectory {
    private final Provider provider;
    public final KeyIvResolver keyIvResolver;
    private final AtomicLong nextTempFileCounter = new AtomicLong();

    public CryptoNIOFSDirectory(LockFactory lockFactory, Path location, Provider provider, KeyIvResolver keyIvResolver) throws IOException {
        super(location, lockFactory);
        this.provider = provider;
        this.keyIvResolver = keyIvResolver;
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        if (name.contains("segments_")
                || name.endsWith(".si")
//            || name.equals("ivFile")
//            || name.equals("keyfile")
//            || name.endsWith(".lock")
        ) {
            return super.openInput(name, context);
        }

        ensureOpen();
        ensureCanRead(name);
        Path path = getDirectory().resolve(name);
        FileChannel fc = FileChannel.open(path, StandardOpenOption.READ);
        boolean success = false;

        try {
            final IndexInput indexInput = new CryptoBufferedIndexInput(
                    "CryptoBufferedIndexInput(path=\"" + path + "\")",
                    fc,
                    context,
                    this.keyIvResolver
            );
            success = true;
            return indexInput;
        } finally {
            if (!success) {
                IOUtils.closeWhileHandlingException(fc);
            }
        }
    }

    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        if (name.contains("segments_")
                || name.endsWith(".si")
//            || name.equals("ivFile")
//            || name.equals("keyfile")
//            || name.endsWith(".lock")
        ) {
            return super.createOutput(name, context);
        }

        ensureOpen();
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        return new CryptoOutputStreamIndexOutput(name, path, fos, this.keyIvResolver, provider);
    }

    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        if (prefix.contains("segments_")
                || prefix.endsWith(".si")
//            || prefix.equals("ivFile")
//            || prefix.equals("keyfile")
//            || prefix.endsWith(".lock")
        ) {
            return super.createTempOutput(prefix, suffix, context);
        }

        ensureOpen();
        String name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        return new CryptoOutputStreamIndexOutput(name, path, fos, this.keyIvResolver, provider);
    }

    @Override
    public long fileLength(String name) throws IOException {
        // Non-encrypted files
        if (name.contains("segments_")
                || name.endsWith(".si")
                || name.equals("ivFile")
                || name.equals("keyfile")
                || name.endsWith(".lock")) {
            return super.fileLength(name);
        }
        
        // Encrypted files
        long fileSize = super.fileLength(name);
        System.err.println("[DEBUG] Processing file: " + name + ", size: " + fileSize + " bytes");
        
        if (fileSize == 0) {
            return 0;
        }
        
        // Proceed with footer processing
        Path path = getDirectory().resolve(name);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            if (fileSize < EncryptionFooter.MIN_FOOTER_SIZE) {
                throw new IOException("File too small to contain encryption footer: " + name + 
                        " (" + fileSize + " bytes, need " + EncryptionFooter.MIN_FOOTER_SIZE + ")");
            }

            ByteBuffer footerBasicBuffer = ByteBuffer.allocate(EncryptionFooter.MIN_FOOTER_SIZE);
            int bytesRead = channel.read(footerBasicBuffer, fileSize - EncryptionFooter.MIN_FOOTER_SIZE);

            if (bytesRead != EncryptionFooter.MIN_FOOTER_SIZE) {
                throw new IOException("Failed to read footer metadata from " + name);
            }

            byte[] footerBytes = footerBasicBuffer.array();
            
            // Log last 28 bytes in hex for debugging
            StringBuilder hexDump = new StringBuilder();
            for (int i = 0; i < footerBytes.length; i++) {
                hexDump.append(String.format("%02X ", footerBytes[i]));
            }
            System.err.println("[DEBUG] File: " + name + ", last " + footerBytes.length + " bytes: " + hexDump.toString());
            
            // Log last 4 bytes specifically (should be magic "OSEF")
            byte[] last4 = new byte[4];
            System.arraycopy(footerBytes, footerBytes.length - 4, last4, 0, 4);
            String last4Str = new String(last4);
            System.err.println("[DEBUG] File: " + name + ", last 4 bytes as string: '" + last4Str + "', as hex: " + 
                    String.format("%02X %02X %02X %02X", last4[0], last4[1], last4[2], last4[3]));

            try {
                int footerLength = EncryptionFooter.calculateFooterLength(footerBytes);
                System.err.println("[DEBUG] File: " + name + ", footer length: " + footerLength + ", logical size: " + (fileSize - footerLength));
                return fileSize - footerLength;
            } catch (IOException e) {
                System.err.println("[DEBUG] File: " + name + ", footer parsing failed: " + e.getMessage());
                throw e;
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        isOpen = false;
        deletePendingFiles();
    }
}
