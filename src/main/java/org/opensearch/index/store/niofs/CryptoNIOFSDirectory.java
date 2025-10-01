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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
    private final Map<String, Long> contentLengthCache = new ConcurrentHashMap<>();

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
                    this.keyResolver
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

        return new CryptoOutputStreamIndexOutput(name, path, fos, this.keyResolver, provider, algorithmId);
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

        return new CryptoOutputStreamIndexOutput(name, path, fos, this.keyResolver, provider, algorithmId);
    }

    @Override
    public long fileLength(String name) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) {
            return super.fileLength(name);
        }

        // Check cache first
        Long cachedLength = contentLengthCache.get(name);
        if (cachedLength != null) {
            return cachedLength;
        }

        long fileSize = super.fileLength(name);
        if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            return Math.max(0, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
        }

        Path path = getDirectory().resolve(name);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            ByteBuffer buffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            channel.read(buffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            int footerLength = EncryptionFooter.calculateFooterLength(buffer.array());
            long contentLength = fileSize - footerLength;
            
            contentLengthCache.put(name, contentLength);
            return contentLength;
        }
    }

    @Override
    public void deleteFile(String name) throws IOException {
        contentLengthCache.remove(name);
        super.deleteFile(name);
    }

    @Override
    public synchronized void close() throws IOException {
        contentLengthCache.clear();
        isOpen = false;
        deletePendingFiles();
    }
}
