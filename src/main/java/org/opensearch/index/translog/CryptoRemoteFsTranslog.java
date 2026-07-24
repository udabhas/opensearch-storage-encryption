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
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.remote.RemoteStorePathStrategy;
import org.opensearch.index.remote.RemoteStoreUtils;
import org.opensearch.index.remote.RemoteTranslogTransferTracker;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;
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
            createCryptoChannelFactory(keyResolver, translogUUID),
            // Use the SAME server-side-encryption flag the recovery READ path resolves
            // (core RemoteFsTranslog.buildTranslogTransferManager -> blobStore(isServerSideEncryptionEnabledIndex)).
            // Hardcoding true made the write path skip the ESDK-wrapping blob store (relying on S3 SSE-KMS),
            // while recovery read wrapped with EncryptedBlobStore -> ESDK-decrypted the plaintext translog
            // metadata blob -> BadCiphertextException("Invalid version") -> shard RED on _close/_open.
            RemoteStoreUtils.isServerSideEncryptionEnabledIndex(config.getIndexSettings().getIndexMetadata())
        );

        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
        this.cryptoFactory = (CryptoChannelFactory) this.channelFactory;

        // After a remote-store restore, S3 holds plaintext translog (GCM stripped on upload) and the
        // download writes those raw bytes to disk, but CryptoChannelFactory expects encrypted files.
        // Re-encrypt old generations to restore the encryption-at-rest invariant.
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
                RemoteStoreUtils.isServerSideEncryptionEnabledIndex(config.getIndexSettings().getIndexMetadata()),
                keyResolver,
                translogUUID,
                cryptoFactory
            );

            // Use reflection to replace the final field
            Field transferManagerField = RemoteFsTranslog.class.getDeclaredField("translogTransferManager");
            transferManagerField.setAccessible(true);
            transferManagerField.set(this, decryptingManager);
        } catch (Exception e) {
            logger.error("Failed to replace TranslogTransferManager with decrypting version", e);
            CryptoMetricsService.getInstance().recordError(ErrorType.TRANSLOG_INIT_ERROR);
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
        boolean isServerSideEncryptionEnabled,
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

        // Must match the container the recovery READ path uses (core RemoteFsTranslog reads translog
        // metadata via blobStore(isServerSideEncryptionEnabled)). If these differ, the metadata blob is
        // written through one container and read through the other -> BadCiphertextException on recovery.
        BlobStoreTransferService transferService = new BlobStoreTransferService(
            blobStoreRepository.blobStore(isServerSideEncryptionEnabled),
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
     * Re-encrypts downloaded plaintext translog files into the self-describing on-disk format (plaintext
     * core header + TLE super-header + length-prefixed AES-GCM frames). Only old generations are processed
     * (not the current writer); files already carrying the super-header magic are skipped to avoid
     * double-encryption. Fail-closed: any conversion failure is rethrown so the shard fails to initialize
     * rather than run on a corrupt or still-plaintext translog. (Recovery readers are already converted in
     * place by {@link CryptoChannelFactory#open}; this sweep covers files recovery did not open.)
     *
     * @throws IOException if a downloaded file cannot be converted to the encrypted format
     */
    private void reEncryptDownloadedTranslogFiles(java.nio.file.Path translogDir, long currentGeneration) throws IOException {
        try (DirectoryStream<java.nio.file.Path> stream = Files.newDirectoryStream(translogDir, "*.tlog")) {
            for (java.nio.file.Path file : stream) {
                String name = file.getFileName().toString();
                // Extract generation number from filename like "translog-4.tlog"
                String genStr = name.replace("translog-", "").replace(".tlog", "");
                long gen;
                try {
                    gen = Long.parseLong(genStr);
                } catch (NumberFormatException e) {
                    continue;
                }

                // Skip current writer generation (already created encrypted by CryptoChannelFactory)
                if (gen >= currentGeneration)
                    continue;

                long fileSize = Files.size(file);
                int headerSize = TranslogFrameManager.calculateTranslogHeaderSizeStatic(translogUUID);

                // Skip header-only files (no data to re-encrypt)
                if (fileSize <= headerSize) {
                    continue;
                }

                java.nio.file.Path tempFile = file.resolveSibling(name + ".tmp");
                try (FileChannel in = FileChannel.open(file, StandardOpenOption.READ)) {
                    // Probe the core header + super-header magic (no Files.readAllBytes: a multi-GB generation
                    // would otherwise load whole into heap, ~2-3x resident, and throw outright above 2 GiB).
                    int probeSize = headerSize + TranslogFrameManager.MAGIC.length;
                    ByteBuffer headerBuf = ByteBuffer.allocate(probeSize);
                    if (readFully(in, headerBuf, 0) < headerSize) {
                        continue; // truncated below the core header
                    }
                    // Detect an already-encrypted translog by super-header MAGIC — skip to avoid double-encryption
                    // and to not mask a format error the reader should fail closed on.
                    if (TranslogFrameManager.hasSuperHeaderMagic(headerBuf.array(), headerSize)) {
                        continue;
                    }

                    try {
                        try (
                            FileChannel out = FileChannel
                                .open(
                                    tempFile,
                                    StandardOpenOption.CREATE,
                                    StandardOpenOption.WRITE,
                                    StandardOpenOption.READ,
                                    StandardOpenOption.TRUNCATE_EXISTING
                                )
                        ) {
                            headerBuf.position(0).limit(headerSize); // core header only, not the magic probe
                            out.write(headerBuf, 0); // plaintext core header passthrough
                            TranslogFrameManager tfm = new TranslogFrameManager(out, keyResolver, file, translogUUID);
                            // Stream the plaintext data region [headerSize, fileSize) through the frame manager
                            // in bounded buffers; the temp channel is the I/O target.
                            ByteBuffer buf = ByteBuffer.allocate(CONVERT_BUFFER_SIZE);
                            long srcPos = headerSize, logicalPos = headerSize;
                            while (srcPos < fileSize) {
                                buf.clear();
                                int n = in.read(buf, srcPos);
                                if (n <= 0) {
                                    break;
                                }
                                buf.flip();
                                while (buf.hasRemaining()) { // append-only: position == headerSize + logicalDataWritten
                                    int accepted = tfm.writeToChunks(buf, logicalPos);
                                    if (accepted <= 0) {
                                        throw new IOException("no progress converting translog file:" + file);
                                    }
                                    logicalPos += accepted;
                                    srcPos += accepted;
                                }
                            }
                            tfm.close();
                            // fsync converted bytes before the atomic rename, else a crash could expose a
                            // partial file under the real translog name. Mirrors ensureEncryptedOnDisk().
                            out.force(true);
                        }
                        Files
                            .move(
                                tempFile,
                                file,
                                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING
                            );
                        // fsync the parent dir so the rename is crash-durable (mirrors core TruncateTranslogAction);
                        // without it a crash can leave the name pointing back at the old plaintext inode.
                        if (file.getParent() != null) {
                            IOUtils.fsync(file.getParent(), true);
                        }
                    } catch (IOException | RuntimeException ex) {
                        // Never leave an orphan temp behind on a mid-conversion failure (the original downloaded
                        // file is untouched until the atomic rename, so deleting the temp is always safe).
                        Files.deleteIfExists(tempFile);
                        throw ex;
                    }
                }
            }
        } catch (IOException e) {
            // Fail closed: do NOT let the shard start on a corrupt/plaintext translog.
            logger.error("Failed to re-encrypt downloaded translog files in {}", translogDir, e);
            CryptoMetricsService.getInstance().recordError(ErrorType.TRANSLOG_INIT_ERROR);
            throw e;
        }
    }

    /** 1 MiB streaming buffer for plaintext->encrypted conversion (avoids loading a whole generation). */
    private static final int CONVERT_BUFFER_SIZE = 1 << 20;

    /** Reads fully into {@code dst} from {@code position}, looping over partial reads; returns bytes read. */
    private static int readFully(FileChannel ch, ByteBuffer dst, long position) throws IOException {
        int total = 0;
        while (dst.hasRemaining()) {
            int n = ch.read(dst, position + total);
            if (n <= 0) {
                break;
            }
            total += n;
        }
        return total;
    }

    /**
     * Helper method to create CryptoChannelFactory for constructor use.
     */
    private static CryptoChannelFactory createCryptoChannelFactory(KeyResolver keyResolver, String translogUUID) throws IOException {
        try {
            return new CryptoChannelFactory(keyResolver, translogUUID);
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.TRANSLOG_INIT_ERROR);
            throw new IOException(
                "Failed to initialize crypto channel factory for translog encryption. Cannot proceed without encryption!",
                e
            );
        }
    }
}
