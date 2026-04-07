/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.engine.EngineConfig;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.engine.InternalEngine;
import org.opensearch.index.engine.NRTReplicationEngine;
import org.opensearch.index.remote.RemoteTranslogTransferTracker;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.index.translog.CryptoTranslogFactory;
import org.opensearch.index.translog.RemoteBlobStoreInternalTranslogFactory;

/**
 * A factory that creates engines with crypto-enabled translogs for cryptofs indices.
 */
public class CryptoEngineFactory implements EngineFactory {
    private static final Logger logger = LogManager.getLogger(CryptoEngineFactory.class);

    /**
     * Default constructor.
     */
    public CryptoEngineFactory() {}

    /**
     * {@inheritDoc}
     */
    @Override
    public Engine newReadWriteEngine(EngineConfig config) {

        try {
            boolean isRemoteTranslogEnabled = config.getIndexSettings().isRemoteTranslogStoreEnabled();
            logger.info("ILE DEBUG CryptoEngineFactory.newReadWriteEngine: shard={}, index={}, isRemoteTranslog={}, isReadOnlyReplica={}, existingTranslogFactory={}, downloadRemoteTranslogOnInit={}",
                config.getShardId(), config.getIndexSettings().getIndex().getName(), isRemoteTranslogEnabled, config.isReadOnlyReplica(),
                config.getTranslogFactory() != null ? config.getTranslogFactory().getClass().getSimpleName() : "null",
                config.getIndexSettings().getIndexMetadata().getSettings().get("index.remote_store.translog.download_on_init", "null"));
            logger.info("ILE DEBUG CryptoEngineFactory.newReadWriteEngine stack trace", new Exception("ILE DEBUG stack trace"));

            // Create a separate KeyResolver for translog encryption
            KeyResolver keyResolver = createTranslogKeyResolver(config);
            logger.info("ILE DEBUG CryptoEngineFactory keyResolver created, keyLen={}", keyResolver.getKey().length);

            // Check if remote translog is enabled
            CryptoTranslogFactory cryptoTranslogFactory;

            if (isRemoteTranslogEnabled) {

                RemoteTranslogTransferTracker tracker;
                if (config.getTranslogFactory() instanceof RemoteBlobStoreInternalTranslogFactory remoteFactory) {
                    tracker = remoteFactory.getRemoteTranslogTransferTracker();
                } else {
                    tracker = new RemoteTranslogTransferTracker(config.getShardId(), 100);
                }
                cryptoTranslogFactory = new CryptoTranslogFactory(
                    keyResolver,
                    CryptoDirectoryPlugin.getRepositoriesServiceSupplier(),
                    config.getThreadPool(),
                    config.getIndexSettings().getRemoteStoreTranslogRepository(),
                    tracker,
                    CryptoDirectoryPlugin.getRemoteStoreSettings()
                );
            } else {
                cryptoTranslogFactory = new CryptoTranslogFactory(keyResolver);
            }
            logger.info("ILE DEBUG CryptoEngineFactory created CryptoTranslogFactory, mode={}", isRemoteTranslogEnabled ? "REMOTE" : "LOCAL");

            // Create new engine config by copying all fields from existing config
            // but replace the translog factory with our crypto version
            EngineConfig cryptoConfig = config.toBuilder().translogFactory(cryptoTranslogFactory).build();

            // in case of replica only we use NRT Replication translog
            if (cryptoConfig.isReadOnlyReplica()) {
                return new NRTReplicationEngine(cryptoConfig);
            }

            // in case of replica only we use NRT Replication translog
            if (cryptoConfig.isReadOnlyReplica()) {
                return new NRTReplicationEngine(cryptoConfig);
            }

            // Return the default engine with crypto-enabled translog
            return new InternalEngine(cryptoConfig);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create crypto engine", e);
        }
    }

    /**
     * Create a separate KeyResolver for translog encryption.
     */
    private KeyResolver createTranslogKeyResolver(EngineConfig config) throws IOException {
        // Create a separate key resolver for translog files

        // Use the translog location for key storage
        // Use index-level keys for translog encryption - same as directory encryption
        Path translogPath = config.getTranslogConfig().getTranslogPath();
        Path indexDirectory = translogPath.getParent().getParent(); // Go up two levels: translog -> shard -> index

        // Get the same settings that CryptoDirectoryFactory uses
        Provider provider = Security.getProvider(CryptoDirectoryFactory.DEFAULT_CRYPTO_PROVIDER);
        MasterKeyProvider keyProvider = getKeyProvider(config);

        // Create directory for index-level keys (same as CryptoDirectoryFactory)
        Directory indexKeyDirectory = FSDirectory.open(indexDirectory);

        // Use shared resolver registry to get the SAME resolver instance as CryptoDirectoryFactory
        String indexUuid = config.getIndexSettings().getIndex().getUUID();
        String indexName = config.getIndexSettings().getIndex().getName();
        int shardId = config.getShardId().getId();
        return ShardKeyResolverRegistry.getOrCreateResolver(indexUuid, indexKeyDirectory, provider, keyProvider, shardId, indexName);
    }

    /**
     * Get the MasterKeyProvider - copied from CryptoDirectoryFactory logic
     */
    private MasterKeyProvider getKeyProvider(EngineConfig config) {
        // Reuse the same logic as CryptoDirectoryFactory
        return new CryptoDirectoryFactory().getKeyProvider(config.getIndexSettings());
    }

}
