/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.zip.CRC32;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.FileSnapshot;

/**
 * Wrapper for TranslogFileSnapshot that provides a decrypting input stream.
 *
 * @opensearch.internal
 */
public class DecryptingFileSnapshot extends FileSnapshot.TranslogFileSnapshot {

    private static final Logger logger = LogManager.getLogger(DecryptingFileSnapshot.class);

    private final TranslogFileSnapshot delegate;
    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final Long decryptedLength;
    private final Long decryptedChecksum;

    /**
     * Creates a new DecryptingFileSnapshot wrapping the provided snapshot.
     *
     * @param delegate the original TranslogFileSnapshot to wrap
     * @param keyResolver the key resolver for decryption
     * @param translogUUID the translog UUID for encryption context (must match encryption!)
     * @throws IOException if snapshot metadata cannot be read
     */
    public DecryptingFileSnapshot(TranslogFileSnapshot delegate, KeyResolver keyResolver, String translogUUID) throws IOException {
        super(
            delegate.getPrimaryTerm(),
            delegate.getGeneration(),
            delegate.getPath(),
            null  // Not passing checksum - decrypted content has different checksum
        );

        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        Path path = delegate.getPath();

        if (path != null && path.getFileName().toString().endsWith(".tlog")) {
            // For encrypted (.tlog) files, count actual decrypted bytes and compute checksum
            try {
                long[] result = measureDecryptedSizeAndChecksum(path);
                this.decryptedLength = result[0];
                this.decryptedChecksum = result[1];
            } catch (Exception e) {
                logger.error("Error measuring decrypted size for {}", path.getFileName(), e);
                throw e;
            }
        } else {
            // For plaintext (.ckp) files, use actual size
            this.decryptedLength = delegate.getContentLength();
            this.decryptedChecksum = delegate.getChecksum();
        }
    }

    /**
     * Measure the actual decrypted size and compute CRC32 checksum by reading through the entire file.
     * 
     * @param path the path to the encrypted translog file
     * @return array of [decryptedSize, crc32Checksum]
     * @throws IOException if file cannot be read or decryption fails
     */
    private long[] measureDecryptedSizeAndChecksum(Path path) throws IOException {
        long totalBytes = 0;
        CRC32 crc32 = new CRC32();
        byte[] buffer = new byte[8192];

        try (CryptoDecryptingInputStream measuringStream = new CryptoDecryptingInputStream(path, keyResolver, translogUUID)) {
            int bytesRead;
            while ((bytesRead = measuringStream.read(buffer)) != -1) {
                totalBytes += bytesRead;
                crc32.update(buffer, 0, bytesRead);
            }
        } catch (Exception e) {
            logger.error("Error reading/decrypting file {}", path.getFileName(), e);
            throw e;
        }

        return new long[] { totalBytes, crc32.getValue() };
    }

    /**
     * Returns a decrypting input stream instead of the raw encrypted stream.
     *
     * @return an InputStream that decrypts the file as it's read
     * @throws IOException if the file cannot be opened or decryption setup fails
     */
    @Override
    public InputStream inputStream() throws IOException {
        // Decrypt .tlog files
        Path path = delegate.getPath();

        if (path != null && path.getFileName().toString().endsWith(".tlog")) {
            return new CryptoDecryptingInputStream(path, keyResolver, translogUUID);
        } else {
            // .ckp files are not encrypted, return normal stream
            return delegate.inputStream();
        }
    }

    /**
     * Returns the metadata file input stream from the delegate.
     */
    @Override
    public InputStream getMetadataFileInputStream() {
        return delegate.getMetadataFileInputStream();
    }

    /**
     * Returns the content length of the decrypted file.
     */
    @Override
    public long getContentLength() throws IOException {
        return decryptedLength;
    }

    /**
     * Returns the CRC32 checksum of the decrypted content.
     */
    @Override
    public Long getChecksum() {
        return decryptedChecksum;
    }

    @Override
    public Path getPath() {
        return delegate.getPath();
    }

    @Override
    public String getName() {
        return delegate.getName();
    }

    @Override
    public long getPrimaryTerm() {
        return delegate.getPrimaryTerm();
    }
}
