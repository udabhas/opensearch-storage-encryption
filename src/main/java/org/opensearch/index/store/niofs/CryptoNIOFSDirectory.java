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
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetrics;

/**
 * A NioFS directory implementation that encrypts files to be stored based on a
 * user supplied key
 *
 * @opensearch.internal
 */
public class CryptoNIOFSDirectory extends NIOFSDirectory {
    private final Provider provider;
    public final KeyResolver keyResolver;
    private final AtomicLong nextTempFileCounter = new AtomicLong();
    private final int algorithmId = 1; // Default to AES_256_GCM_CTR

    public CryptoNIOFSDirectory(LockFactory lockFactory, Path location, Provider provider, KeyResolver keyResolver) throws IOException {
        super(location, lockFactory);
        this.provider = provider;
        this.keyResolver = keyResolver;
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) {
            return super.openInput(name, context);
        }

        long startTime = System.currentTimeMillis();
        boolean success = false;
        long fileSize = 0;
        
        try {
            ensureOpen();
            ensureCanRead(name);
            Path path = getDirectory().resolve(name);
            fileSize = fileLength(name); // Get decrypted file size
            FileChannel fc = FileChannel.open(path, StandardOpenOption.READ);
            boolean fcSuccess = false;

            try {
                final IndexInput indexInput = new CryptoBufferedIndexInput(
                    "CryptoBufferedIndexInput(path=\"" + path + "\")",
                    fc,
                    context,
                    this.keyResolver
                );
                fcSuccess = true;
                success = true;
                return indexInput;
            } finally {
                if (!fcSuccess) {
                    IOUtils.closeWhileHandlingException(fc);
                }
            }
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            CryptoMetrics.getInstance().recordOperation(duration, "decrypt", success, fileSize);
        }
    }

    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) {
            return super.createOutput(name, context);
        }

        long startTime = System.currentTimeMillis();
        boolean success = false;
        
        try {
            ensureOpen();
            Path path = directory.resolve(name);
            OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);
            
            IndexOutput output = new CryptoOutputStreamIndexOutput(name, path, fos, this.keyResolver, provider, algorithmId);
            success = true;
            return output;
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            // For output creation, we don't know final size yet, so use 0
            CryptoMetrics.getInstance().recordOperation(duration, "encrypt", success, 0);
        }
    }

    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        if (prefix.contains("segments_") || prefix.endsWith(".si")) {
            return super.createTempOutput(prefix, suffix, context);
        }

        long startTime = System.currentTimeMillis();
        boolean success = false;
        
        try {
            ensureOpen();
            String name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
            Path path = directory.resolve(name);
            OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

            IndexOutput output = new CryptoOutputStreamIndexOutput(name, path, fos, this.keyResolver, provider, algorithmId);
            success = true;
            return output;
        } finally {
            long duration = System.currentTimeMillis() - startTime;
            // For temp output creation, we don't know final size yet, so use 0
            CryptoMetrics.getInstance().recordOperation(duration, "encrypt", success, 0);
        }
    }

    @Override
    public long fileLength(String name) throws IOException {
        if ((name.contains("segments_") || name.endsWith(".si")) ) {
            return super.fileLength(name);  // Non-encrypted files
        }
        
        // Encrypted files: calculate variable footer length
        long fileSize = super.fileLength(name);
        // Handle files that might be in process of being written
        if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            // File might be incomplete or very small
            return Math.max(0, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);  // Assume minimum footer
        }
        
        Path path = getDirectory().resolve(name);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            // Read minimum footer to get actual length
            ByteBuffer buffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            channel.read(buffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            
            int footerLength = EncryptionFooter.calculateFooterLength(buffer.array());
            return fileSize - footerLength;
        }
    }

    @Override
    public synchronized void close() throws IOException {
        isOpen = false;
        deletePendingFiles();
    }
}