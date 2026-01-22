/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;

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
 * @opensearch.internal
 */
public class DecryptingTranslogTransferManager extends TranslogTransferManager {

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
        TransferSnapshot decryptingSnapshot = new DecryptingTransferSnapshot(transferSnapshot, keyResolver, translogUUID, cryptoFactory);

        // Call parent with decryption wrapper
        return super.transferSnapshot(decryptingSnapshot, translogTransferListener, cryptoMetadata);
    }
}
