/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.opensearch.index.remote.RemoteStoreEnums.DataCategory.TRANSLOG;
import static org.opensearch.index.remote.RemoteStoreEnums.DataType.DATA;
import static org.opensearch.index.remote.RemoteStoreEnums.DataType.METADATA;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.concurrent.Semaphore;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.blobstore.BlobPath;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.remote.RemoteStorePathStrategy;
import org.opensearch.index.remote.RemoteTranslogTransferTracker;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.BlobStoreTransferService;
import org.opensearch.index.translog.transfer.FileTransferTracker;
import org.opensearch.index.translog.transfer.TranslogTransferManager;
import org.opensearch.indices.RemoteStoreSettings;
import org.opensearch.repositories.blobstore.BlobStoreRepository;
import org.opensearch.threadpool.ThreadPool;

/**
 * A RemoteFsTranslog implementation that provides AES-GCM encryption capabilities
 * with decrypt-before-upload for remote store.
 *
 * This class extends RemoteFsTranslog and:
 * 1. Injects CryptoChannelFactory for local file encryption (AES-GCM)
 * 2. Uses DecryptingTranslogTransferManager to decrypt before upload
 * 3. Allows S3 to apply SSE-KMS with index-level key
 * 4. Results in single encryption layer in S3 (no double encryption)
 *
 * The decrypt-before-upload flow is handled entirely in the plugin by
 * DecryptingTranslogTransferManager, which wraps snapshots with
 * DecryptingTransferSnapshot to provide decrypting input streams.
 *
 * All crypto logic stays in the plugin - core remains unaware.
 *
 * @opensearch.internal
 */
public class CryptoRemoteFsTranslog extends RemoteFsTranslog {

    private static final Logger logger = LogManager.getLogger(CryptoRemoteFsTranslog.class);

    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final CryptoChannelFactory cryptoFactory;
    private static final int SYNC_PERMIT = 1;
    private final Semaphore syncPermit = new Semaphore(SYNC_PERMIT);

    /**
     * Creates a new CryptoRemoteFsTranslog with AES-GCM encryption and remote store support.
     *
     * @param config the translog configuration
     * @param translogUUID the translog UUID (used for both encryption context and transfer manager)
     * @param deletionPolicy the deletion policy
     * @param globalCheckpointSupplier the global checkpoint supplier
     * @param primaryTermSupplier the primary term supplier
     * @param persistedSequenceNumberConsumer the persisted sequence number consumer
     * @param blobStoreRepository the blob store repository for remote storage
     * @param threadPool the thread pool
     * @param startedPrimarySupplier the started primary supplier
     * @param remoteTranslogTransferTracker the remote translog transfer tracker
     * @param remoteStoreSettings the remote store settings
     * @param translogOperationHelper the translog operation helper
     * @param keyResolver the key resolver for encryption (unified with index files)
     * @throws IOException if translog creation fails
     */
    public CryptoRemoteFsTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        BlobStoreRepository blobStoreRepository,
        ThreadPool threadPool,
        BooleanSupplier startedPrimarySupplier,
        RemoteTranslogTransferTracker remoteTranslogTransferTracker,
        RemoteStoreSettings remoteStoreSettings,
        TranslogOperationHelper translogOperationHelper,
        KeyResolver keyResolver
    )
        throws IOException {
        // // Strict validation FIRST - before anything else
        // if (keyResolver == null || translogUUID == null) {
        // throw new IllegalArgumentException(
        // "Cannot create CryptoRemoteFsTranslog without keyResolver and translogUUID. "
        // + "Required for translog encryption. keyResolver="
        // + keyResolver
        // + ", translogUUID="
        // + translogUUID
        // );
        // }

        // CRITICAL FIX: Create factory ONCE and use it in both places!
        // This ensures we finalize cipher on the SAME factory that creates channels
        // CryptoChannelFactory factory = createCryptoChannelFactory(keyResolver, translogUUID);

        super(
            config,
            translogUUID,
            deletionPolicy,
            globalCheckpointSupplier,
            primaryTermSupplier,
            persistedSequenceNumberConsumer,
            blobStoreRepository,
            threadPool,
            startedPrimarySupplier,
            remoteTranslogTransferTracker,
            remoteStoreSettings,
            translogOperationHelper,
            createCryptoChannelFactory(keyResolver, translogUUID),  // Use the SAME factory instance
            true // isServerSideEncryptionEnabled - signals SSE-KMS usage
        );

        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        // this.cryptoFactory = factory; // Store reference to SAME factory
        this.cryptoFactory = (CryptoChannelFactory) this.channelFactory;
        // this.channelFactory;
        // CRITICAL: Replace the parent's transfer manager with our decrypting version!
        // Parent created a regular TranslogTransferManager, we need DecryptingTranslogTransferManager
        // The translogTransferManager field is protected AND final, so we use reflection

        try {
            TranslogTransferManager decryptingManager = createDecryptingTranslogTransferManager(
                blobStoreRepository,
                threadPool,
                config.getShardId(),
                fileTransferTracker,
                remoteTranslogTransferTracker,
                config.getIndexSettings().getRemoteStorePathStrategy(),
                remoteStoreSettings,
                config.getIndexSettings().isTranslogMetadataEnabled(),
                keyResolver,
                translogUUID,  // Pass the translogUUID from constructor
                cryptoFactory  // CRITICAL: Pass the factory for path-based cipher finalization!
            );

            // Use reflection to replace the final field
            Field transferManagerField = RemoteFsTranslog.class.getDeclaredField("translogTransferManager");
            transferManagerField.setAccessible(true);
            transferManagerField.set(this, decryptingManager);
        } catch (Exception e) {
            logger.error("Failed to replace TranslogTransferManager with decrypting version", e);
            throw new IOException("Failed to initialize decrypt-before-upload capability", e);
        }
    }

    /**
     * Creates a DecryptingTranslogTransferManager to replace parent's regular manager.
     * 
     * This is the KEY method that enables decrypt-before-upload!
     * The DecryptingTranslogTransferManager wraps snapshots with DecryptingTransferSnapshot,
     * which provides decrypting input streams during upload.
     */
    private static TranslogTransferManager createDecryptingTranslogTransferManager(
        BlobStoreRepository blobStoreRepository,
        ThreadPool threadPool,
        ShardId shardId,
        FileTransferTracker fileTransferTracker,
        RemoteTranslogTransferTracker tracker,
        RemoteStorePathStrategy pathStrategy,
        RemoteStoreSettings remoteStoreSettings,
        boolean isTranslogMetadataEnabled,
        KeyResolver keyResolver,
        String translogUUID,
        CryptoChannelFactory cryptoFactory
    ) {
        String indexUUID = shardId.getIndex().getUUID();
        String shardIdStr = String.valueOf(shardId.id());

        RemoteStorePathStrategy.ShardDataPathInput dataPathInput = RemoteStorePathStrategy.ShardDataPathInput
            .builder()
            .basePath(blobStoreRepository.basePath())
            .indexUUID(indexUUID)
            .shardId(shardIdStr)
            .dataCategory(TRANSLOG)
            .dataType(DATA)
            .fixedPrefix(remoteStoreSettings.getTranslogPathFixedPrefix())
            .build();
        BlobPath dataPath = pathStrategy.generatePath(dataPathInput);

        RemoteStorePathStrategy.ShardDataPathInput mdPathInput = RemoteStorePathStrategy.ShardDataPathInput
            .builder()
            .basePath(blobStoreRepository.basePath())
            .indexUUID(indexUUID)
            .shardId(shardIdStr)
            .dataCategory(TRANSLOG)
            .dataType(METADATA)
            .fixedPrefix(remoteStoreSettings.getTranslogPathFixedPrefix())
            .build();
        BlobPath mdPath = pathStrategy.generatePath(mdPathInput);

        BlobStoreTransferService transferService = new BlobStoreTransferService(
            blobStoreRepository.blobStore(true), // SSE-KMS enabled
            threadPool
        );

        // Return our decrypting version with the REAL translogUUID and cryptoFactory!
        // CRITICAL: This translogUUID must match what was used for encryption in CryptoChannelFactory
        // CRITICAL: cryptoFactory enables path-based cipher finalization before upload
        return new DecryptingTranslogTransferManager(
            shardId,
            transferService,
            dataPath,
            mdPath,
            fileTransferTracker,
            tracker,
            remoteStoreSettings,
            isTranslogMetadataEnabled,
            keyResolver, // Pass keyResolver for decryption!
            translogUUID, // FIX: Pass the REAL translogUUID from constructor parameter!
            cryptoFactory // FIX: Pass cryptoFactory for path-based cipher finalization!
        );
    }

    /**
     * Helper method to create CryptoChannelFactory for constructor use.
     * Returns concrete CryptoChannelFactory type so we can use finalizeCurrentCipher().
     */
    private static CryptoChannelFactory createCryptoChannelFactory(KeyResolver keyResolver, String translogUUID) throws IOException {
        try {
            return new CryptoChannelFactory(keyResolver, translogUUID);
        } catch (Exception e) {
            logger.error("Failed to initialize CryptoChannelFactory: {}", e.getMessage(), e);
            throw new IOException(
                "Failed to initialize crypto channel factory for translog encryption. Cannot proceed without encryption!",
                e
            );
        }
    }
}
