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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
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
 * @opensearch.internal
 */
public class CryptoRemoteFsTranslog extends RemoteFsTranslog {

    private static final Logger logger = LogManager.getLogger(CryptoRemoteFsTranslog.class);

    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final CryptoChannelFactory cryptoFactory;

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
            logAndCreateFactory(config, translogUUID, keyResolver),
            true // isServerSideEncryptionEnabled
        );

        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        this.cryptoFactory = (CryptoChannelFactory) this.channelFactory;

        // ILE DEBUG: after super() returns
        logger.info("ILE DEBUG CryptoRemoteFsTranslog AFTER super() files on disk: {}", listFilesWithSizes(config.getTranslogPath()));
        try (DirectoryStream<java.nio.file.Path> stream = Files.newDirectoryStream(config.getTranslogPath(), "*.tlog")) {
            for (java.nio.file.Path p : stream) {
                logger.info("ILE DEBUG CryptoRemoteFsTranslog hex dump {}: {}", p.getFileName(), hexDumpFirst64(p));
            }
        } catch (Exception e) { logger.warn("ILE DEBUG hex dump failed", e); }
        logger.info("ILE DEBUG CryptoRemoteFsTranslog readers.size={}, current.generation={}", readers.size(), current.getGeneration());

        // Re-encrypt downloaded plaintext translog files with the new key.
        // After remote store restore, S3 has plaintext translog data (AES-GCM was stripped
        // during upload by DecryptingTranslogTransferManager). The download writes these raw
        // plaintext bytes to disk. But CryptoChannelFactory expects AES-GCM encrypted files
        // on disk. We re-encrypt old generation files so the decrypt-before-upload path works
        // and the encryption-at-rest invariant is maintained.
        reEncryptDownloadedTranslogFiles(config.getTranslogPath(), current.getGeneration());

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
                translogUUID,
                cryptoFactory
            );

            // Use reflection to replace the final field
            Field transferManagerField = RemoteFsTranslog.class.getDeclaredField("translogTransferManager");
            transferManagerField.setAccessible(true);
            transferManagerField.set(this, decryptingManager);
            logger.info("ILE DEBUG CryptoRemoteFsTranslog reflection replacement of translogTransferManager succeeded");
        } catch (Exception e) {
            logger.error("Failed to replace TranslogTransferManager with decrypting version", e);
            throw new IOException("Failed to initialize decrypt-before-upload capability", e);
        }
    }

    /**
     * Creates a DecryptingTranslogTransferManager to replace parent's manager.
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

        return new DecryptingTranslogTransferManager(
            shardId,
            transferService,
            dataPath,
            mdPath,
            fileTransferTracker,
            tracker,
            remoteStoreSettings,
            isTranslogMetadataEnabled,
            keyResolver,
            translogUUID,
            cryptoFactory
        );
    }

    /**
     * Re-encrypts downloaded plaintext translog files with the current key.
     * Only processes old generation .tlog files (not the current writer).
     * Files that are already encrypted (size doesn't match plaintext expectations) are skipped.
     */
    private void reEncryptDownloadedTranslogFiles(java.nio.file.Path translogDir, long currentGeneration) {
        try (DirectoryStream<java.nio.file.Path> stream = Files.newDirectoryStream(translogDir, "*.tlog")) {
            for (java.nio.file.Path file : stream) {
                String name = file.getFileName().toString();
                // Extract generation number from filename like "translog-4.tlog"
                String genStr = name.replace("translog-", "").replace(".tlog", "");
                long gen;
                try { gen = Long.parseLong(genStr); } catch (NumberFormatException e) { continue; }

                // Skip current writer generation (already created encrypted by CryptoChannelFactory)
                if (gen >= currentGeneration) continue;

                long fileSize = Files.size(file);
                int headerSize = TranslogChunkManager.calculateTranslogHeaderSizeStatic(translogUUID);

                // Skip header-only files (no data to re-encrypt)
                if (fileSize <= headerSize) {
                    logger.info("ILE DEBUG reEncrypt: skipping {} (header-only, size={})", name, fileSize);
                    continue;
                }

                // Read the entire plaintext file
                byte[] plainBytes = Files.readAllBytes(file);
                byte[] header = java.util.Arrays.copyOf(plainBytes, headerSize);
                byte[] data = java.util.Arrays.copyOfRange(plainBytes, headerSize, plainBytes.length);

                // Check if file is already encrypted by attempting decryption.
                // If decryption succeeds, the file is already encrypted → skip.
                // If it fails (AEADBadTagException), the file is plaintext → re-encrypt.
                byte[] baseIV = org.opensearch.index.store.key.HkdfKeyDerivation.deriveTranslogBaseIV(
                    keyResolver.getDataKey().getEncoded(), translogUUID
                );
                byte[] chunkIV = org.opensearch.index.store.cipher.AesCipherFactory.computeOffsetIVForAesGcmEncrypted(baseIV, 0);

                try {
                    org.opensearch.index.store.cipher.AesGcmCipherFactory.decryptWithTag(keyResolver.getDataKey(), chunkIV, data);
                    // Decryption succeeded → file is already encrypted with current key, skip
                    logger.info("ILE DEBUG reEncrypt: skipping {} (already encrypted, size={})", name, fileSize);
                    continue;
                } catch (org.opensearch.index.store.cipher.AesGcmCipherFactory.JavaCryptoException e) {
                    // Decryption failed → file is plaintext, proceed with re-encryption
                    logger.info("ILE DEBUG reEncrypt: {} is plaintext (decrypt failed), will re-encrypt", name);
                }

                // Encrypt the data portion (IV already derived above)
                byte[] encrypted;
                try {
                    encrypted = org.opensearch.index.store.cipher.AesGcmCipherFactory.encryptWithTag(
                        keyResolver.getDataKey(), chunkIV, data, data.length
                    );
                } catch (org.opensearch.index.store.cipher.AesGcmCipherFactory.JavaCryptoException e) {
                    throw new IOException("Failed to encrypt translog data for " + name, e);
                }

                // Write header + encrypted data back to file
                java.nio.file.Path tempFile = file.resolveSibling(name + ".tmp");
                try (FileChannel out = FileChannel.open(tempFile,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                    out.write(ByteBuffer.wrap(header));
                    out.write(ByteBuffer.wrap(encrypted));
                }
                Files.move(tempFile, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

                logger.info("ILE DEBUG reEncrypt: re-encrypted {} (plaintext={}B → encrypted={}B)",
                    name, fileSize, headerSize + encrypted.length);
            }
        } catch (Exception e) {
            logger.error("ILE DEBUG reEncrypt: failed to re-encrypt translog files", e);
        }
    }

    private static String listFilesWithSizes(java.nio.file.Path dir) {
        StringBuilder sb = new StringBuilder();
        try (DirectoryStream<java.nio.file.Path> stream = Files.newDirectoryStream(dir)) {
            for (java.nio.file.Path p : stream) {
                sb.append(p.getFileName()).append("=").append(Files.size(p)).append(" ");
            }
        } catch (Exception e) { sb.append("ERROR: ").append(e.getMessage()); }
        return sb.toString();
    }

    private static String hexDumpFirst64(java.nio.file.Path file) {
        try (FileChannel fc = FileChannel.open(file, StandardOpenOption.READ)) {
            int toRead = (int) Math.min(64, fc.size());
            ByteBuffer buf = ByteBuffer.allocate(toRead);
            fc.read(buf);
            buf.flip();
            StringBuilder sb = new StringBuilder();
            while (buf.hasRemaining()) sb.append(String.format("%02x", buf.get()));
            return sb.toString();
        } catch (Exception e) { return "ERROR: " + e.getMessage(); }
    }

    private static CryptoChannelFactory logAndCreateFactory(TranslogConfig config, String translogUUID, KeyResolver keyResolver) throws IOException {
        logger.info("ILE DEBUG CryptoRemoteFsTranslog constructor: translogUUID={}, downloadRemoteTranslogOnInit={}, key={}",
            translogUUID, config.getIndexSettings().getIndexMetadata().getSettings().get("index.remote_store.translog.download_on_init", "null"), keyResolver.getDataKey());
        logger.info("ILE DEBUG CryptoRemoteFsTranslog BEFORE super() files on disk: {}", listFilesWithSizes(config.getTranslogPath()));
        return createCryptoChannelFactory(keyResolver, translogUUID);
    }

    /**
     * Helper method to create CryptoChannelFactory for constructor use.
     */
    private static CryptoChannelFactory createCryptoChannelFactory(KeyResolver keyResolver, String translogUUID) throws IOException {
        try {
            return new CryptoChannelFactory(keyResolver, translogUUID);
        } catch (Exception e) {
            throw new IOException(
                "Failed to initialize crypto channel factory for translog encryption. Cannot proceed without encryption!",
                e
            );
        }
    }
}
