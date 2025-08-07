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
    private final int algorithmId = 1; // Default to AES_256_GCM_CTR

    public CryptoNIOFSDirectory(LockFactory lockFactory, Path location, Provider provider, KeyIvResolver keyIvResolver) throws IOException {
        super(location, lockFactory);
        this.provider = provider;
        this.keyIvResolver = keyIvResolver;
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) {
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
        if (name.contains("segments_") || name.endsWith(".si")) {
            return super.createOutput(name, context);
        }

        ensureOpen();
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        return new CryptoOutputStreamIndexOutput(name, path, fos, this.keyIvResolver, provider, algorithmId);
    }

    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        if (prefix.contains("segments_") || prefix.endsWith(".si")) {
            return super.createTempOutput(prefix, suffix, context);
        }

        ensureOpen();
        String name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        return new CryptoOutputStreamIndexOutput(name, path, fos, this.keyIvResolver, provider, algorithmId);
    }

    @Override
    public long fileLength(String name) throws IOException {
        if (isNonEncryptedFile(name)) {
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

    private boolean isNonEncryptedFile(String name) {
        return name.contains("segments_") ||
                name.endsWith(".si") ||
                name.equals("ivFile") ||
                name.equals("keyfile") ||
                name.endsWith(".lock");
    }
}
