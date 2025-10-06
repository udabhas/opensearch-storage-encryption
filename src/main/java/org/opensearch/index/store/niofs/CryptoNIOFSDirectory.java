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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.apache.lucene.store.NIOFSDirectory;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.index.store.CryptoDirectoryFactory;
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
    private final Map<String, EncryptionFooter> footerCache = new ConcurrentHashMap<>();
    private static final Logger LOGGER = LogManager.getLogger(CryptoNIOFSDirectory.class);

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
            // Get cached footer or read once
            EncryptionFooter footer = getOrReadFooter(name, fc);
            
            final IndexInput indexInput = new CryptoBufferedIndexInput(
                    "CryptoBufferedIndexInput(path=\"" + path + "\")",
                    fc,
                    context,
                    this.keyResolver,
                    footer  // Pass cached footer
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
//            return Math.max(0, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            return fileSize;
        }

        Path path = getDirectory().resolve(name);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            ByteBuffer buffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            channel.read(buffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            int footerLength;
            try {
                footerLength = EncryptionFooter.calculateFooterLength(buffer.array());
            } catch (Exception ex) {
                LOGGER.error("Got error during calculateFooterLength", ex);
                return fileSize;
            }

            long contentLength = fileSize - footerLength;
            if (contentLength < 0) {
                return fileSize;
            }
            contentLengthCache.put(name, contentLength);
            return contentLength;
        }
    }

    private EncryptionFooter getOrReadFooter(String name, FileChannel fc) throws IOException {
        return footerCache.computeIfAbsent(name, fileName -> {
            try {
                return readFooterFromFile(fc);
            } catch (IOException e) {
                throw new RuntimeException("Failed to read footer for " + fileName, e);
            }
        });
    }

    private EncryptionFooter readFooterFromFile(FileChannel channel) throws IOException {
        long fileSize = channel.size();
        if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            throw new IOException("File too small to contain encryption footer");
        }
        
        ByteBuffer minBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
        channel.read(minBuffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
        
        int footerLength = EncryptionFooter.calculateFooterLength(minBuffer.array());
        
        ByteBuffer footerBuffer = ByteBuffer.allocate(footerLength);
        channel.read(footerBuffer, fileSize - footerLength);
        
        return EncryptionFooter.deserialize(footerBuffer.array(), keyResolver.getDataKey().getEncoded());
    }

    @Override
    public void deleteFile(String name) throws IOException {
        contentLengthCache.remove(name);
        footerCache.remove(name);
        super.deleteFile(name);
    }

    @Override
    public synchronized void close() throws IOException {
        contentLengthCache.clear();
        footerCache.clear();
        isOpen = false;
        deletePendingFiles();
    }
}
