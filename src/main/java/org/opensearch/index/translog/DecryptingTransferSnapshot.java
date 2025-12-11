/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.FileSnapshot.TransferFileSnapshot;
import org.opensearch.index.translog.transfer.FileSnapshot.TranslogFileSnapshot;
import org.opensearch.index.translog.transfer.TransferSnapshot;
import org.opensearch.index.translog.transfer.TranslogTransferMetadata;

/**
 * Wrapper for TransferSnapshot that provides decrypted file streams during upload.
 * 
 * This class implements the decorator pattern to intercept file snapshot requests
 * and wrap them with DecryptingFileSnapshot instances. This enables the decrypt-before-upload
 * flow where:
 * 
 * 1. Local files remain encrypted with AES-GCM
 * 2. During upload, files are decrypted on-the-fly
 * 3. Plaintext is uploaded to S3
 * 4. S3 applies SSE-KMS with index-level key
 * 5. Result: Single encryption layer in S3 (no double encryption)
 * 
 * All crypto logic stays in the plugin - core remains unaware of encryption/decryption.
 *
 * @opensearch.internal
 */
public class DecryptingTransferSnapshot implements TransferSnapshot {

    private static final Logger logger = LogManager.getLogger(DecryptingTransferSnapshot.class);

    private final TransferSnapshot delegate;
    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final CryptoChannelFactory cryptoFactory;

    /**
     * Creates a new DecryptingTransferSnapshot wrapping the provided snapshot.
     *
     * @param delegate the original TransferSnapshot to wrap
     * @param keyResolver the key resolver for decryption
     * @param translogUUID the translog UUID for encryption context (must match encryption!)
     * @param cryptoFactory the crypto channel factory for finalizing ciphers
     */
    public DecryptingTransferSnapshot(
        TransferSnapshot delegate,
        KeyResolver keyResolver,
        String translogUUID,
        CryptoChannelFactory cryptoFactory
    ) {
        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        this.cryptoFactory = cryptoFactory;
    }

    /**
     * Returns translog file snapshots wrapped with decrypting capability.
     * 
     * Each TranslogFileSnapshot is wrapped with DecryptingFileSnapshot which
     * provides a decrypting input stream when read.
     */
    @Override
    public Set<TransferFileSnapshot> getTranslogFileSnapshots() {
        try {
            Set<TransferFileSnapshot> originals = delegate.getTranslogFileSnapshots();
            return wrapTranslogSnapshots(originals);
        } catch (Exception e) {
            logger.error("Failed to wrap translog snapshots", e);
            throw new RuntimeException("Failed to wrap translog snapshots", e);
        }
    }

    /**
     * Returns translog file snapshots with metadata, wrapped with decrypting capability.
     * 
     * This is used when metadata (checkpoint) needs to be associated with translog files.
     */
    @Override
    public Set<TransferFileSnapshot> getTranslogFileSnapshotWithMetadata() throws IOException {
        try {
            Set<TransferFileSnapshot> originals = delegate.getTranslogFileSnapshotWithMetadata();
            return wrapTranslogSnapshots(originals);
        } catch (IOException e) {
            logger.error("IOException wrapping translog snapshots with metadata", e);
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error wrapping translog snapshots with metadata", e);
            throw new IOException("Failed to wrap translog snapshots", e);
        }
    }

    /**
     * Returns checkpoint file snapshots without modification.
     * 
     * Checkpoint files are not encrypted, so they don't need decryption wrapping.
     */
    @Override
    public Set<TransferFileSnapshot> getCheckpointFileSnapshots() {
        // Checkpoint files are not encrypted, return as-is
        return delegate.getCheckpointFileSnapshots();
    }

    /**
     * Returns the transfer metadata from the delegate without modification.
     * 
     * Metadata contains generation info, primary term, etc. - no encryption involved.
     */
    @Override
    public TranslogTransferMetadata getTranslogTransferMetadata() {
        return delegate.getTranslogTransferMetadata();
    }

    /**
     * Wraps translog file snapshots with DecryptingFileSnapshot.
     * 
     * Only TranslogFileSnapshot instances are wrapped; other types pass through unchanged.
     * This ensures only .tlog files get the decrypting treatment.
     */
    private Set<TransferFileSnapshot> wrapTranslogSnapshots(Set<TransferFileSnapshot> originals) throws IOException {
        Set<TransferFileSnapshot> wrapped = new java.util.HashSet<>();

        for (TransferFileSnapshot snapshot : originals) {
            if (snapshot instanceof TranslogFileSnapshot) {
                TranslogFileSnapshot translogSnapshot = (TranslogFileSnapshot) snapshot;
                java.nio.file.Path path = translogSnapshot.getPath();

                // CRITICAL: Finalize cipher for this specific file BEFORE wrapping!
                // This writes authentication tags so the file can be decrypted during upload
                cryptoFactory.finalizeForPath(path);

                // Now wrap translog files with decrypting capability
                wrapped.add(new DecryptingFileSnapshot(translogSnapshot, keyResolver, translogUUID));
            } else {
                // Other file types (if any) pass through unchanged
                wrapped.add(snapshot);
            }
        }

        return wrapped;
    }
}
