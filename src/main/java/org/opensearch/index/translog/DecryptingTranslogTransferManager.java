/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.CryptoMetadata;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.remote.RemoteTranslogTransferTracker;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.FileTransferTracker;
import org.opensearch.index.translog.transfer.TransferService;
import org.opensearch.index.translog.transfer.TransferSnapshot;
import org.opensearch.index.translog.transfer.TranslogTransferManager;
import org.opensearch.index.translog.transfer.listener.TranslogTransferListener;
import org.opensearch.indices.RemoteStoreSettings;

/**
 * Extension of TranslogTransferManager that applies decryption wrapping before upload.
 * 
 * This class intercepts the transferSnapshot() call and wraps the snapshot with
 * DecryptingTransferSnapshot, which provides decrypting input streams for translog files.
 * 
 * This is the cleanest injection point because:
 * - No need to override Translog methods that call private parent methods
 * - Works at the exact point where upload happens
 * - Keeps all crypto logic in the plugin
 * - Avoids IllegalAccessError from plugin trying to access core's private methods
 *
 * @opensearch.internal
 */
public class DecryptingTranslogTransferManager extends TranslogTransferManager {

    private static final Logger logger = LogManager.getLogger(DecryptingTranslogTransferManager.class);

    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final CryptoChannelFactory cryptoFactory;

    /**
     * Creates a new DecryptingTranslogTransferManager with decryption capability.
     *
     * @param shardId the shard ID
     * @param transferService the transfer service
     * @param remoteDataTransferPath the remote data path
     * @param remoteMetadataTransferPath the remote metadata path
     * @param fileTransferTracker the file transfer tracker
     * @param remoteTranslogTransferTracker the remote translog transfer tracker
     * @param remoteStoreSettings the remote store settings
     * @param isTranslogMetadataEnabled whether translog metadata is enabled
     * @param keyResolver the key resolver for decryption
     * @param translogUUID the translog UUID for encryption context (must match encryption!)
     * @param cryptoFactory the crypto channel factory for finalizing ciphers
     */
    public DecryptingTranslogTransferManager(
        ShardId shardId,
        TransferService transferService,
        BlobPath remoteDataTransferPath,
        BlobPath remoteMetadataTransferPath,
        FileTransferTracker fileTransferTracker,
        RemoteTranslogTransferTracker remoteTranslogTransferTracker,
        RemoteStoreSettings remoteStoreSettings,
        boolean isTranslogMetadataEnabled,
        KeyResolver keyResolver,
        String translogUUID,
        CryptoChannelFactory cryptoFactory
    ) {
        super(
            shardId,
            transferService,
            remoteDataTransferPath,
            remoteMetadataTransferPath,
            fileTransferTracker,
            remoteTranslogTransferTracker,
            remoteStoreSettings,
            isTranslogMetadataEnabled
        );
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        this.cryptoFactory = cryptoFactory;
    }

    /**
     * Overrides transferSnapshot to inject decryption wrapper.
     * 
     * This is the CRITICAL injection point where we wrap the snapshot with
     * DecryptingTransferSnapshot. The flow is:
     * 
     * 1. Parent creates TranslogCheckpointTransferSnapshot (encrypted local files)
     * 2. We wrap it with DecryptingTransferSnapshot (provides decrypting streams)
     * 3. Parent's upload logic reads from our decrypting streams
     * 4. Plaintext bytes are uploaded to S3
     * 5. S3 applies SSE-KMS with index-level key (from CryptoMetadata)
     * 6. Result: Single encryption layer in S3 (no double encryption!)
     *
     * @param transferSnapshot the snapshot to transfer
     * @param translogTransferListener the transfer listener
     * @param cryptoMetadata the crypto metadata for SSE-KMS
     * @return true if transfer succeeded
     * @throws IOException if transfer fails
     */
    @Override
    public boolean transferSnapshot(
        TransferSnapshot transferSnapshot,
        TranslogTransferListener translogTransferListener,
        CryptoMetadata cryptoMetadata
    ) throws IOException {
        // CRITICAL: Wrap with decrypting capability! Pass translogUUID for proper decryption context
        // and cryptoFactory for path-based cipher finalization.
        TransferSnapshot decryptingSnapshot = new DecryptingTransferSnapshot(transferSnapshot, keyResolver, translogUUID, cryptoFactory);

        // Call parent with our decrypting wrapper
        return super.transferSnapshot(decryptingSnapshot, translogTransferListener, cryptoMetadata);
    }
}
