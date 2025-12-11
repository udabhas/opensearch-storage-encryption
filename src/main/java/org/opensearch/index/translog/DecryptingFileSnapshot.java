/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.FileSnapshot;

/**
 * Wrapper for TranslogFileSnapshot that provides a decrypting input stream.
 * 
 * This class uses composition (not inheritance) to wrap TranslogFileSnapshot since
 * it's a final class. It delegates all method calls to the wrapped snapshot except
 * for inputStream() which returns a CryptoDecryptingInputStream, and getContentLength()
 * which returns the decrypted content length.
 * 
 * This ensures that when core uploads the translog to S3, it uploads plaintext bytes
 * with correct metadata (size, no checksum since decrypted content differs from encrypted).
 *
 * @opensearch.internal
 */
public class DecryptingFileSnapshot extends FileSnapshot.TranslogFileSnapshot {

    private static final Logger logger = LogManager.getLogger(DecryptingFileSnapshot.class);

    private final TranslogFileSnapshot delegate;
    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final Long decryptedLength;

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
            null  // Don't pass checksum - decrypted content has different checksum
        );

        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;

        // Calculate decrypted length for .tlog files
        Path path = delegate.getPath();

        if (path != null && path.getFileName().toString().endsWith(".tlog")) {
            // For encrypted translog files, count actual decrypted bytes
            // This is the most accurate approach - read the file once to measure size
            try {
                this.decryptedLength = measureDecryptedSize(path);
            } catch (Exception e) {
                logger.error("Error measuring decrypted size for {}", path.getFileName(), e);
                throw e;
            }
        } else {
            // For non-encrypted files (checkpoints), use actual size
            this.decryptedLength = delegate.getContentLength();
        }
    }

    /**
     * Measure the actual decrypted size by reading through the entire file.
     * 
     * This is the most accurate method - we decrypt the file once to count bytes,
     * then decrypt it again during upload. Small performance cost but ensures
     * exact size match to avoid CRC32 errors.
     * 
     * @param path the path to the encrypted translog file
     * @return the exact number of decrypted bytes
     * @throws IOException if file cannot be read or decryption fails
     */
    private long measureDecryptedSize(Path path) throws IOException {
        long totalBytes = 0;
        byte[] buffer = new byte[8192];

        try (CryptoDecryptingInputStream measuringStream = new CryptoDecryptingInputStream(path, keyResolver, translogUUID)) {
            int bytesRead;
            while ((bytesRead = measuringStream.read(buffer)) != -1) {
                totalBytes += bytesRead;
            }
        } catch (Exception e) {
            logger.error("Error reading/decrypting file {}", path.getFileName(), e);
            throw e;
        }

        return totalBytes;
    }

    /**
     * Returns a decrypting input stream instead of the raw encrypted stream.
     *
     * This is the critical override that enables decrypt-before-upload.
     * When core reads from this stream during upload, it receives plaintext bytes.
     *
     * @return an InputStream that decrypts the file as it's read
     * @throws IOException if the file cannot be opened or decryption setup fails
     */
    @Override
    public InputStream inputStream() throws IOException {
        // Only decrypt .tlog files, not checkpoint files
        Path path = delegate.getPath();

        if (path != null && path.getFileName().toString().endsWith(".tlog")) {
            return new CryptoDecryptingInputStream(path, keyResolver, translogUUID);
        } else {
            // Checkpoint files are not encrypted, return normal stream
            return delegate.inputStream();
        }
    }

    /**
     * Returns the metadata file input stream from the delegate.
     * Checkpoint file streams are not encrypted.
     */
    @Override
    public InputStream getMetadataFileInputStream() {
        return delegate.getMetadataFileInputStream();
    }

    /**
     * Returns the content length of the decrypted file.
     * 
     * For encrypted .tlog files, this is the plaintext size (without GCM tags).
     * For checkpoint files, this is the actual file size.
     * 
     * CRITICAL: This must match the actual bytes that inputStream() will provide,
     * otherwise S3 will reject the upload with CRC32/size mismatch errors.
     */
    @Override
    public long getContentLength() throws IOException {
        return decryptedLength;
    }

    /**
     * Returns null checksum since decrypted content has different checksum than encrypted file.
     * 
     * S3 will calculate checksum from the uploaded plaintext content, which is correct.
     * We don't want to provide the encrypted file's checksum as it won't match.
     */
    @Override
    public Long getChecksum() {
        // Return null - S3 will calculate checksum from plaintext we upload
        return null;
    }

    // Delegate all other methods to the wrapped snapshot

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
