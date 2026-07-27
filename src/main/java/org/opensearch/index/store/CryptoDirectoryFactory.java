/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.LockFactory;
import org.opensearch.cluster.metadata.CryptoMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Setting.Property;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.crypto.CryptoHandlerRegistry;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.shard.ShardPath;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.block_loader.CryptoDirectIOBlockLoader;
import org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.cipher.EncryptionMetadataCacheRegistry;
import org.opensearch.index.store.hybrid.HybridCryptoDirectory;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.index.store.kms_encryption_context.EncryptionContextResolver;
import org.opensearch.index.store.kms_encryption_context.EncryptionContextResolverFactory;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.index.store.pool.PoolBuilder;
import org.opensearch.index.store.read_ahead.Worker;
import org.opensearch.plugins.IndexStorePlugin;

/**
 * Factory for creating encrypted filesystem directories with support for various storage types.
 *
 * <p>Supports:
 * <ul>
 * <li>NIOFS: NIO-based encrypted file system</li>
 * <li>HYBRIDFS: Hybrid directory with Direct I/O and block caching</li>
 * <li>MMAPFS: Not supported (throws AssertionError)</li>
 * </ul>
 *
 * <p>The factory maintains node-level shared resources (pool and cache) for efficient
 * memory utilization across all encrypted directories.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "temporary")
public class CryptoDirectoryFactory implements IndexStorePlugin.DirectoryFactory {

    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectoryFactory.class);

    /**
     * Shared pool resources including pool, cache, and telemetry.
     * Lazily initialized on first cryptofs shard creation and shared across all CryptoBufferPoolFSDirectory instances.
     * This prevents resource allocation on dedicated master nodes which never create shards.
     */
    private static volatile PoolBuilder.PoolResources poolResources;

    /**
     * Node settings used for lazy pool initialization.
     */
    private static volatile Settings nodeSettings;

    /**
     * Current value of {@code node.store.crypto.proactive_shrink_enabled} (dynamic cluster setting).
     * Stored statically so it can (a) seed the monitor when the pool is lazily built, and (b) be flipped
     * on the live pool at runtime via {@link #setProactiveShrinkEnabled(boolean)}. Default OFF.
     */
    private static volatile boolean proactiveShrinkEnabled = false;

    /**
     * Apply the proactive-shrink enabled flag: remember it (so a not-yet-built pool picks it up at init)
     * and, if the shared pool already exists, flip its monitor live. Called from the plugin's dynamic
     * settings update-consumer and once at pool build time.
     */
    public static void setProactiveShrinkEnabled(boolean enabled) {
        proactiveShrinkEnabled = enabled;
        PoolBuilder.PoolResources r = poolResources;
        if (r != null && r.getSegmentPool() instanceof org.opensearch.index.store.pool.MemorySegmentPool msp) {
            msp.proactiveMonitor().setEnabled(enabled);
        }
    }

    /** @return the current proactive-shrink enabled flag (read by PoolBuilder to seed the monitor). */
    public static boolean isProactiveShrinkEnabled() {
        return proactiveShrinkEnabled;
    }

    /**
     * Lock for thread-safe initialization of shared resources.
     */
    private static final Object initLock = new Object();

    /**
     * Resolver for obtaining default encryption context from cluster metadata.
     * Abstracted to allow Amazon-specific logic to be maintained separately.
     */
    private static volatile EncryptionContextResolver encryptionContextResolver;

    /**
     * Creates a new CryptoDirectoryFactory
     */
    public CryptoDirectoryFactory() {
        super();
    }

    /**
     * Store type identifier for encrypted filesystem directories.
     */
    public static final String STORE_TYPE = "cryptofs";

    /**
     * Base setting prefix for crypto-related index settings.
     */
    public static final String CRYPTO_SETTING = "index.store.crypto";

    /**
     * Default crypto provider name.
     */
    public static final String DEFAULT_CRYPTO_PROVIDER = "SunJCE";

    /**
     * Specifies the Key management plugin type to be used. The desired CryptoKeyProviderPlugin
     * plugin should be installed.
     */
    public static final Setting<String> INDEX_KEY_PROVIDER_SETTING = new Setting<>(
        "index.store.crypto.key_provider",
        "",
        Function.identity(),
        (s) -> {
            if (s == null || s.isEmpty()) {
                throw new SettingsException("index.store.crypto.key_provider must be set");
            }
        },
        Property.NodeScope,
        Property.IndexScope,
        Property.InternalIndex
    );

    /**
     * AWS KMS key ARN for index-level encryption.
     * Specifies the Amazon Resource Name of the KMS key used as master key for encrypting index data.
     */
    public static final Setting<String> INDEX_KMS_ARN_SETTING = new Setting<>(
        "index.store.crypto.kms.key_arn",
        "",
        Function.identity(),
        (s) -> {
            if (s == null || s.isEmpty()) {
                throw new SettingsException("index.store.kms.arn must be set");
            }
        },
        Property.IndexScope,
        Property.InternalIndex
    );

    /**
     * AWS KMS encryption context for additional authenticated data.
     * Provides extra security by requiring the same context for both encrypt and decrypt operations.
    */
    public static final Setting<String> INDEX_KMS_ENC_CTX_SETTING = new Setting<>(
        "index.store.crypto.kms.encryption_context",
        Constants.DEFAULT_KMS_ENC_CTX,
        Function.identity(),
        Property.IndexScope,
        Property.InternalIndex
    );

    /**
     * Specifies the node-level interval for proactive health monitoring of encryption keys.
     * The health monitor periodically validates all encrypted indices and attempts to refresh their keys,
     * providing early detection of issues and automatic recovery.
     * 
     * Default: 1 hour (1h)
     * Minimum: 1 second (1s) - must be positive
     * 
     * This setting applies globally to all indices.
     * 
     * Supported units: s (seconds), m (minutes), h (hours), d (days)
     * Examples: 30s, 5m, 1h, 2h
     */
    public static final Setting<TimeValue> NODE_KEY_REFRESH_INTERVAL_SETTING = Setting
        .timeSetting(
            "node.store.crypto.key_refresh_interval",
            TimeValue.timeValueHours(1),  // default: 1 hour
            TimeValue.timeValueSeconds(1),  // minimum: 1 second (must be positive)
            Property.NodeScope
        );

    /**
     * Specifies the node-level expiration time for cached encryption keys.
     * Keys are evicted from cache after this duration and must be reloaded from the key provider.
     * 
     * Default: 24 hours (24h)
     * Set to -1 to never expire keys (cache forever until node restart).
     * 
     * This setting applies globally to all indices.
     * 
     * Supported units: s (seconds), m (minutes), h (hours), d (days)
     * Examples: 60s, 10m, 3h, 12h, -1 (never expire)
     */
    public static final Setting<TimeValue> NODE_KEY_EXPIRY_INTERVAL_SETTING = Setting
        .timeSetting(
            "node.store.crypto.key_expiry_interval",
            TimeValue.timeValueHours(24),  // default: 24 hours
            TimeValue.timeValueSeconds(-1),  // minimum: -1 means never expire
            Property.NodeScope
        );

    /**
     * Get default encryption context from cluster metadata using the configured resolver.
     *
     * @return the encryption context from cluster settings, or empty string if not found
     */
    private String getDefaultEncryptionContextFromCluster() {
        if (encryptionContextResolver == null) {
            return "";
        }

        return encryptionContextResolver.resolveDefaultEncryptionContext();
    }

    MasterKeyProvider getKeyProvider(IndexSettings indexSettings) {
        final String KEY_PROVIDER = indexSettings.getValue(INDEX_KEY_PROVIDER_SETTING);

        // Handle dummy type for testing
        if (KeyProviderType.DUMMY.getValue().equals(KEY_PROVIDER)) {
            LOGGER.debug("Using dummy key provider for testing");
            return DummyKeyProvider.create();
        }

        Settings settings = indexSettings.getSettings().getAsSettings(CRYPTO_SETTING);

        // Always try to get default encryption context from cluster repositories as a baseline
        String defaultEncCtx = getDefaultEncryptionContextFromCluster();
        String indexEncCtx = settings.get("kms.encryption_context");

        // Merge default encryption context with index-specific context
        if (!defaultEncCtx.isEmpty()) {
            if (indexEncCtx == null || indexEncCtx.isEmpty()) {
                // Use default encryption context if index doesn't specify one
                LOGGER
                    .info(
                        "Using default encryption context from cluster repository for index {}: {}",
                        indexSettings.getIndex().getName(),
                        defaultEncCtx
                    );
                settings = Settings.builder().put(settings).put("kms.encryption_context", defaultEncCtx).build();
            } else {
                // Merge: default context is the baseline, index context is additional
                String mergedEncCtx = defaultEncCtx + "," + indexEncCtx;
                LOGGER
                    .info(
                        "Merging default encryption context '{}' with index-specific context '{}' for index {}: result='{}'",
                        defaultEncCtx,
                        indexEncCtx,
                        indexSettings.getIndex().getName(),
                        mergedEncCtx
                    );
                settings = Settings.builder().put(settings).put("kms.encryption_context", mergedEncCtx).build();
            }
        }

        CryptoMetadata cryptoMetadata = new CryptoMetadata(KEY_PROVIDER, "", settings);
        MasterKeyProvider keyProvider;
        try {
            keyProvider = CryptoHandlerRegistry.getInstance().getCryptoKeyProviderPlugin(KEY_PROVIDER).createKeyProvider(cryptoMetadata);
        } catch (NullPointerException npe) {
            throw new RuntimeException("could not find key provider: " + KEY_PROVIDER, npe);
        }
        return keyProvider;
    }

    /**
     * {@inheritDoc}
     *
     * @param indexSettings the index settings
     * @param path the shard file path
     */
    @Override
    public Directory newDirectory(IndexSettings indexSettings, ShardPath path) throws IOException {
        validateNotS3VectorIndex(indexSettings);

        try {
            final Path location = path.resolveIndex();
            final LockFactory lockFactory = indexSettings.getValue(org.opensearch.index.store.FsDirectoryFactory.INDEX_LOCK_FACTOR_SETTING);
            Files.createDirectories(location);
            return newFSDirectory(location, lockFactory, indexSettings);
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.DIRECTORY_CREATION_ERROR);
            throw e;
        }
    }

    /**
     * Handles keyfile copying for clone/resize operations.
     * When an index is cloned, Lucene copies the ciphertext segment files verbatim,
     * but if we generate a new key for the target index, decryption will fail.
     * This method detects clone operations and copies the source keyfile to the target.
     *
     * Package-private for testing.
     *
     * @param indexSettings the index settings
     * @param targetIndexDirectory the target index directory path
     * @throws IOException if keyfile copy fails
     */
    void handleResizeOperation(IndexSettings indexSettings, Path targetIndexDirectory) throws IOException {
        // Check for resize source UUID setting (indicates clone/shrink/split operation)
        String resizeSourceUuid = indexSettings.getSettings().get("index.resize.source.uuid");
        String resizeSourceName = indexSettings.getSettings().get("index.resize.source.name");

        if (resizeSourceUuid == null || resizeSourceUuid.isEmpty()) {
            // Not a resize operation, proceed with normal key generation
            return;
        }

        LOGGER
            .info(
                "Detected resize operation for index {} from source index {} (UUID: {})",
                indexSettings.getIndex().getName(),
                resizeSourceName,
                resizeSourceUuid
            );

        // Determine source index directory path
        Path targetParent = targetIndexDirectory.getParent(); // indices/
        Path sourceIndexDirectory = targetParent.resolve(resizeSourceUuid);

        Path sourceKeyfile = sourceIndexDirectory.resolve("keyfile");
        Path targetKeyfile = targetIndexDirectory.resolve("keyfile");

        // Check if source keyfile exists
        if (!Files.exists(sourceKeyfile)) {
            LOGGER
                .warn(
                    "[Resize operation] for index {} from source index {} which does not have index-level encryption enabled. "
                        + "Target index will generate a new encryption key.",
                    indexSettings.getIndex().getName(),
                    resizeSourceName
                );
            return;
        }

        // Now, check if target keyfile already exists
        // This can happen when multiple shards are initialized concurrently on the same node
        // and another shard has already copied the keyfile
        if (Files.exists(targetKeyfile)) {
            LOGGER
                .debug(
                    "[Resize operation] encryption keyfile already exists at {} for index {}"
                        + "Skipping copy as it was likely created by another shard initialization.",
                    targetKeyfile,
                    indexSettings.getIndex().getName()
                );
            return;
        }

        // Copy keyfile from source to target
        try {
            Files.copy(sourceKeyfile, targetKeyfile);
            LOGGER.debug("Successfully copied keyfile from {} to {} for resize operation", sourceKeyfile, targetKeyfile);
        } catch (IOException e) {
            throw new IOException(
                "[Resize operation] Failed to copy keyfile from source index "
                    + resizeSourceName
                    + " to target index "
                    + indexSettings.getIndex().getName(),
                e
            );
        }
    }

    /**
     * Creates an encrypted directory based on the configured store type.
     *
     * @param location the directory location
     * @param lockFactory the lock factory for this directory
     * @param indexSettings the index settings
     * @return the concrete implementation of the encrypted directory based on store type
     * @throws IOException if directory creation fails
     */
    public Directory newFSDirectory(Path location, LockFactory lockFactory, IndexSettings indexSettings) throws IOException {
        // Extract shardId from path structure: .../indices/{index-uuid}/{shard-id}/index/
        // location.getParent() gives us the shard directory
        int shardId = Integer.parseInt(location.getParent().getFileName().toString());
        final Provider provider = Security.getProvider(DEFAULT_CRYPTO_PROVIDER);

        // Use index-level key resolver - store keys at index level

        Path indexDirectory = location.getParent().getParent(); // Go up two levels: index -> shard -> index
        MasterKeyProvider keyProvider = getKeyProvider(indexSettings);

        // Create a directory for the index-level keys
        Directory indexKeyDirectory = FSDirectory.open(indexDirectory);

        // Check if this is a clone/resize operation
        handleResizeOperation(indexSettings, indexDirectory);

        // Use shared resolver registry to prevent race conditions
        String indexUuid = indexSettings.getIndex().getUUID();
        String indexName = indexSettings.getIndex().getName();
        KeyResolver keyResolver = ShardKeyResolverRegistry
            .getOrCreateResolver(indexUuid, indexKeyDirectory, provider, keyProvider, shardId, indexName);

        // Get or create per-shard encryption metadata cache
        EncryptionMetadataCache encryptionMetadataCache = EncryptionMetadataCacheRegistry.getOrCreateCache(indexUuid, shardId, indexName);

        IndexModule.Type type = IndexModule.defaultStoreType(IndexModule.NODE_STORE_ALLOW_MMAP.get(indexSettings.getNodeSettings()));

        switch (type) {
            case HYBRIDFS -> {
                LOGGER.debug("Using HYBRIDFS directory with Direct I/O and block caching");
                final Set<String> nioExtensions = new HashSet<>(indexSettings.getValue(IndexModule.INDEX_STORE_HYBRID_NIO_EXTENSIONS));
                // Route stored-fields data (.fdt) through the BufferPool (Direct I/O + block cache) rather
                // than the NIO path. The BufferPool IndexInput (CachedMemorySegmentIndexInput) implements
                // IndexInput.prefetch() (async ForkJoinPool block loading); the NIO path does not, so with
                // .fdt on NIO the Lucene stored-fields prefetch call hits a no-op. Removing "fdt" here lets
                // stored-fields reads use the block cache and participate in async prefetch.
                nioExtensions.remove("fdt");
                BufferPoolDirectory bufferPoolDirectory = createCryptoBufferPoolFSDirectory(
                    location,
                    lockFactory,
                    provider,
                    keyResolver,
                    encryptionMetadataCache
                );
                return new HybridCryptoDirectory(
                    lockFactory,
                    bufferPoolDirectory,
                    provider,
                    keyResolver,
                    encryptionMetadataCache,
                    nioExtensions
                );
            }
            case MMAPFS -> {
                LOGGER.info("MMAPFS not supported natively for index-level-encryption; using bufferpoolfs with block caching");
                return createCryptoBufferPoolFSDirectory(location, lockFactory, provider, keyResolver, encryptionMetadataCache);
            }
            case SIMPLEFS, NIOFS -> {
                LOGGER.debug("Using NIOFS directory for encrypted storage");
                return new CryptoNIOFSDirectory(lockFactory, location, provider, keyResolver, encryptionMetadataCache);
            }
            default -> throw new AssertionError("unexpected built-in store type [" + type + "]");
        }
    }

    @SuppressWarnings("unchecked")
    private BufferPoolDirectory createCryptoBufferPoolFSDirectory(
        Path location,
        LockFactory lockFactory,
        Provider provider,
        KeyResolver keyResolver,
        EncryptionMetadataCache encryptionMetadataCache
    ) throws IOException {
        /*
        * ================================
        * Shared Block Cache Architecture
        * ================================
        *
        * This method creates a CryptoBufferPoolFSDirectory that uses node-level shared resources
        * (pool and cache) for efficient memory utilization and high cache hit rates.
        *
        * Shared Resources:
        * -----------------
        * - sharedSegmentPool: Pool of RefCountedByteBuffers (initialized in initializeSharedPool)
        * - sharedBlockCache: Caffeine cache storing decrypted blocks (initialized in initializeSharedPool)
        * - sharedRadixBlockTableRegistry: per-file L1 RadixBlockTable registry, wired to the
        *   shared cache's eviction listener so L2 evictions clear the corresponding L1 entry
        *
        * Per-Directory Resources:
        * ------------------------
        * - BlockLoader: Directory-specific loader using this directory's keyIvResolver for decryption
        * - Cache Wrapper: Wraps the shared cache with directory-specific loader
        * - ReadAhead Worker: Asynchronous prefetching for sequential reads
        *
        * Memory Lifecycle (GC-managed RefCountedByteBuffer):
        * ---------------------------------------------------
        * 1. Cache miss: Loader reads encrypted data, decrypts it into a direct ByteBuffer wrapped
        *    in a RefCountedByteBuffer (no refcount, no generation, no manual close).
        * 2. The block is held strongly by the Caffeine L2 cache (and referenced from L1).
        * 3. Readers access the buffer's MemorySegment directly; there is no pin/unpin.
        * 4. On L2 eviction the entry loses its strong reference; the JVM Cleaner frees the
        *    backing direct buffer once it becomes unreachable. There is no recycle/reset of a
        *    wrapper, so the segment-recycle race class is structurally impossible.
        *
        * L1/L2 Coherence (prevents stale reads):
        * ---------------------------------------
        * - evictionListener: registry.onEviction() nulls the stale L1 (RadixBlockTable) slot
        *   BEFORE the value is closed, so future reads see a clean L1 miss and re-resolve via L2.
        */

        // Ensure pool resources are initialized before creating directory
        PoolBuilder.PoolResources resources = ensurePoolInitialized();

        // Create a per-directory loader that uses this directory's keyIvResolver for decryption
        BlockLoader<RefCountedByteBuffer> loader = new CryptoDirectIOBlockLoader(
            resources.getSegmentPool(),
            keyResolver,
            encryptionMetadataCache
        );

        // Cache architecture: One shared Caffeine cache storage, multiple wrapper instances
        // - sharedBlockCache: Created once in ensurePoolInitialized(), holds the actual cache storage
        // - directoryCache: Per-directory wrapper that shares the underlying cache but uses its own loader
        // This design allows:
        // * Shared cache capacity across all directories
        // * Per-directory decryption via directory-specific loaders with unique keyIvResolvers
        // * Unified eviction policy managed by the shared cache (incl. the L1 eviction listener,
        // which is wired once on the shared cache in PoolBuilder.build())
        CaffeineBlockCache<RefCountedByteBuffer, RefCountedByteBuffer> sharedCaffeineCache =
            (CaffeineBlockCache<RefCountedByteBuffer, RefCountedByteBuffer>) resources.getBlockCache();

        BlockCache<RefCountedByteBuffer> directoryCache = new CaffeineBlockCache<>(
            sharedCaffeineCache.getCache(),
            loader,
            resources.getMaxCacheBlocks(),
            sharedCaffeineCache
        );

        // Use the shared node-wide read-ahead worker
        // All shards/directories share a single queue and executor pool for better resource utilization
        Worker readaheadWorker = resources.getSharedReadaheadWorker();

        return new BufferPoolDirectory(
            location,
            lockFactory,
            provider,
            keyResolver,
            resources.getSegmentPool(),
            directoryCache,
            loader,
            readaheadWorker,
            encryptionMetadataCache,
            resources.getRadixBlockTableRegistry()
        );
    }

    /**
     * Set node settings for lazy pool initialization.
     * Called from CryptoDirectoryPlugin.createComponents() during node startup.
     *
     * @param settings the node settings for configuration
     */
    public static void setNodeSettings(Settings settings) {
        nodeSettings = settings;
    }

    /**
     * Set cluster service for accessing cluster metadata and initialize encryption context resolver.
     * Called from CryptoDirectoryPlugin.createComponents() during node startup.
     *
     * @param service the cluster service
     */
    public static void setClusterService(ClusterService service) {
        // Initialize encryption context resolver
        encryptionContextResolver = EncryptionContextResolverFactory.create(service);
    }

    /**
     * Lazily initialize the shared MemorySegmentPool and BlockCache on first cryptofs shard creation.
     * This prevents resource allocation on dedicated master nodes which never create shards.
     *
     * Thread Safety:
     * - Uses double-checked locking for initialization -- safe.
     *
     * @return the initialized pool resources
     */
    @SuppressWarnings("DoubleCheckedLocking")
    private static PoolBuilder.PoolResources ensurePoolInitialized() {
        if (poolResources == null) {
            synchronized (initLock) {
                if (poolResources == null) {
                    if (nodeSettings == null) {
                        throw new IllegalStateException("Node settings must be set before initializing pool resources");
                    }
                    LOGGER.info("Lazily initializing shared pool resources on first cryptofs shard creation");
                    poolResources = PoolBuilder.build(nodeSettings);
                }
            }
        }
        return poolResources;
    }

    /**
     * Close the shared pool resources if they were initialized.
     * Called from CryptoDirectoryPlugin.close() during node shutdown.
     */
    public static void closeSharedPool() {
        if (poolResources != null) {
            poolResources.close();
        }
        closeFileChannelCache();
    }

    /**
     * Get the shared block cache instance.
     * This can be used for cache invalidation when indices or shards are deleted.
     *
     * @return the shared block cache, or null if not initialized
     */
    public static BlockCache<?> getSharedBlockCache() {
        return poolResources != null ? poolResources.getBlockCache() : null;
    }

    /**
     * Flush ALL node-level plugin caches so the next read is served from disk + decrypted afresh.
     * This is the "flush API" — used to force a genuinely COLD cryptofs cache for benchmarking
     * (e.g. cold-vs-cold search comparisons). It clears, in coherence order:
     *
     * <ol>
     *   <li>L2 block cache ({@link BlockCache#clear()}) — firing the eviction listener that clears
     *       matching L1 slots and closes the pooled {@code RefCountedByteBuffer} values.</li>
     *   <li>L1 radix tables ({@code RadixBlockTableRegistry.clearContents()}) — belt-and-suspenders
     *       for any remnant not covered by the per-block eviction callback.</li>
     *   <li>Per-shard encryption metadata/footer cache ({@code EncryptionMetadataCacheRegistry.clearAll()}).</li>
     *   <li>Node-level read {@code FileChannel} cache ({@link #closeFileChannelCache()}).</li>
     * </ol>
     *
     * <p>The {@link org.opensearch.index.store.pool.MemorySegmentPool} has no freelist — pooled
     * direct buffers are reclaimed by the JVM {@code Cleaner} once unreferenced. After clearing the
     * caches (which drop those references) this method requests {@code System.gc()} and POLLS
     * {@code getBuffersInUse()} until it settles to ~0 or a timeout elapses, so the caller can VERIFY
     * the off-heap pool actually drained rather than trusting a fire-and-forget.
     *
     * <p>Safe to call between queries (no in-flight read): unlike the serverless {@code clearSafely}
     * hack there is no refcount dance — we assume no concurrent search holds a block.
     *
     * <p>NODE-SCOPED: clears only THIS node's caches. A multi-node cluster would need a
     * TransportNodesAction fan-out; out of scope for the single-node benchmark harness.
     *
     * @return a result map with before/after counters (initialized, buffersInUse before/after,
     *         L2 entries cleared, gc rounds, whether the pool settled, elapsed millis)
     */
    public static java.util.Map<String, Object> flushAllCaches() {
        java.util.Map<String, Object> result = new java.util.LinkedHashMap<>();
        PoolBuilder.PoolResources r = poolResources;
        if (r == null) {
            result.put("initialized", false);
            result.put("note", "shared pool not initialized (no cryptofs shard created yet)");
            return result;
        }
        long startNanos = System.nanoTime();
        result.put("initialized", true);

        BlockCache<?> blockCache = r.getBlockCache();
        org.opensearch.index.store.bufferpoolfs.RadixBlockTableRegistry radix = r.getRadixBlockTableRegistry();
        org.opensearch.index.store.pool.MemorySegmentPool pool = (r
            .getSegmentPool() instanceof org.opensearch.index.store.pool.MemorySegmentPool msp) ? msp : null;

        int buffersBefore = (pool != null) ? pool.getBuffersInUse() : -1;
        long l2Before = (blockCache != null) ? blockCache.getCacheSize() : -1;
        int metaBefore = EncryptionMetadataCacheRegistry.getCacheSize();
        result.put("buffersInUse_before", buffersBefore);
        result.put("l2_entries_before", l2Before);
        result.put("metadata_entries_before", metaBefore);

        LOGGER.info("flushAllCaches: starting — evicting plugin caches (L2={}, L1 registry, metadata={})", l2Before, metaBefore);
        // 1) L2 clear -> eviction listener clears matching L1 + closes buffers.
        if (blockCache != null) {
            LOGGER.info("flushAllCaches: [1/4] clearing L2 block cache ({} entries)", l2Before);
            blockCache.clear();
        }
        // 2) L1 belt-and-suspenders.
        if (radix != null) {
            LOGGER.info("flushAllCaches: [2/4] clearing L1 radix tables");
            radix.clearContents();
        }
        // 3) per-shard metadata/footer cache (messageId + derived-key material).
        LOGGER.info("flushAllCaches: [3/4] clearing encryption metadata/footer cache ({} entries)", metaBefore);
        EncryptionMetadataCacheRegistry.clearAll();
        // 4) node-level read FileChannel cache (closes cached FDs via removal listener).
        LOGGER.info("flushAllCaches: [4/4] closing node FileChannel cache; requesting GC + polling pool drain");
        closeFileChannelCache();

        // 5+6) request GC and poll until the pool's in-use buffer count settles (Cleaner reclaims
        // the now-unreferenced direct buffers). System.gc() is a request, not a guarantee, so we
        // poll with a timeout and report whether it actually settled (fail-loud, no false "cold").
        // System.gc() is advisory: the Cleaner reclaims unreferenced direct buffers on its own
        // schedule, and a small residual (structural refs + GC-pending "zombie" buffers) is normal
        // and does NOT keep queries warm (verified: reads still hit disk with buffersInUse in the
        // low thousands but pool utilization <1%). So we do NOT wait for buffersInUse==0; we GC and
        // poll until the count STABILIZES (stops falling across two polls) or a timeout elapses, and
        // report the residual so the caller can see utilization is negligible rather than trusting
        // a false absolute-zero target.
        int gcRounds = 0;
        boolean settled = false;
        int buffersAfter = buffersBefore;
        if (pool != null) {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
            int prev = buffersBefore;
            int stableStreak = 0;
            while (System.nanoTime() < deadline) {
                System.gc();
                gcRounds++;
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                buffersAfter = pool.getBuffersInUse();
                // Stable = no further decrease for 3 consecutive polls (Cleaner has drained what it will).
                if (buffersAfter >= prev) {
                    if (++stableStreak >= 3) {
                        settled = true;
                        break;
                    }
                } else {
                    stableStreak = 0;
                }
                prev = buffersAfter;
            }
            buffersAfter = pool.getBuffersInUse();
        }
        result.put("buffersInUse_after", buffersAfter);
        result.put("l2_entries_after", (blockCache != null) ? blockCache.getCacheSize() : -1);
        result.put("metadata_entries_after", EncryptionMetadataCacheRegistry.getCacheSize());
        result.put("gc_rounds", gcRounds);
        result.put("pool_settled", settled);
        result.put("elapsed_ms", (System.nanoTime() - startNanos) / 1_000_000L);
        LOGGER
            .info(
                "flushAllCaches: buffersInUse {}->{} (settled={}), L2 {}->{}, meta {}->{}, gcRounds={}, {}ms",
                buffersBefore,
                buffersAfter,
                settled,
                l2Before,
                result.get("l2_entries_after"),
                metaBefore,
                result.get("metadata_entries_after"),
                gcRounds,
                result.get("elapsed_ms")
            );
        return result;
    }

    /**
     * Node-level cache of read-only {@link FileChannel}s, keyed by absolute file path. Lets the
     * Direct-I/O read path (see {@code CryptoDirectIOBlockLoader} / {@code FileChannelBackend}) reuse
     * an open channel across block-cache misses instead of paying an {@code open()}/{@code close()}
     * syscall pair per load. This is safe to share across threads because every read goes through the
     * <em>positional</em> {@code FileChannel.read(buffer, position)} form in
     * {@link org.opensearch.index.store.block_loader.DirectIOReaderUtil#directIOReadAligned} — positional
     * reads do not touch the channel's shared position, so concurrent readers do not interfere.
     *
     * <p>The cache is size-bounded and the removal listener CLOSES the evicted channel — without that,
     * evicting an entry would leak the file descriptor. Callers that hit a {@link java.nio.channels.ClosedChannelException}
     * (entry evicted+closed mid-read, or after deleteFile) must fall back to a fresh one-shot channel.
     */
    private static volatile com.github.benmanes.caffeine.cache.Cache<String, FileChannel> fileChannelCache;

    /** Max number of open FileChannels to keep cached per node. Bounded to cap FD usage. */
    private static final int FILE_CHANNEL_CACHE_MAX = 2048;

    /**
     * Lazily create (once) and return the node-level FileChannel cache. Double-checked locking on
     * {@link #initLock} mirrors the other shared-resource accessors in this factory.
     *
     * @return the shared FileChannel cache
     */
    public static com.github.benmanes.caffeine.cache.Cache<String, FileChannel> getOrCreateFileChannelCache() {
        com.github.benmanes.caffeine.cache.Cache<String, FileChannel> local = fileChannelCache;
        if (local == null) {
            synchronized (initLock) {
                local = fileChannelCache;
                if (local == null) {
                    local = com.github.benmanes.caffeine.cache.Caffeine
                        .newBuilder()
                        .maximumSize(FILE_CHANNEL_CACHE_MAX)
                        .removalListener((String key, FileChannel ch, com.github.benmanes.caffeine.cache.RemovalCause cause) -> {
                            if (ch != null) {
                                try {
                                    ch.close();
                                } catch (IOException e) {
                                    LOGGER.debug("Failed to close evicted cached FileChannel for {}: {}", key, e.toString());
                                }
                            }
                        })
                        .build();
                    fileChannelCache = local;
                }
            }
        }
        return local;
    }

    /**
     * Close + drop all cached FileChannels (closes FDs via the removal listener).
     * Called from {@link #closeSharedPool()} during node shutdown.
     */
    public static void closeFileChannelCache() {
        com.github.benmanes.caffeine.cache.Cache<String, FileChannel> local = fileChannelCache;
        if (local != null) {
            local.invalidateAll();
            local.cleanUp();
        }
    }

    /**
     * Cache key for a file's cached read {@link FileChannel}. MUST be the single source of truth for
     * the key format so producers (the backend that populates the cache) and consumers (delete/rename
     * invalidation) can never drift — a mismatch would silently leave a stale FD cached against a
     * reused path, and because the data read path is unauthenticated AES-CTR that surfaces only later
     * as corruption rather than failing fast.
     *
     * @param filePath the file path
     * @return the cache key
     */
    public static String fileChannelCacheKey(Path filePath) {
        return "dio:" + filePath.toAbsolutePath().normalize().toString();
    }

    /**
     * Invalidate (and close, via the removal listener) the cached {@link FileChannel} for a single
     * file. MUST be called whenever a file is deleted, renamed, or replaced at a path that may be
     * reused — otherwise a later open of the reused path could read old-inode ciphertext through the
     * stale cached FD while the footer/file-key is re-read from the new inode.
     *
     * @param filePath the file whose cached channel should be dropped
     */
    public static void invalidateFileChannel(Path filePath) {
        com.github.benmanes.caffeine.cache.Cache<String, FileChannel> local = fileChannelCache;
        if (local != null) {
            local.invalidate(fileChannelCacheKey(filePath));
        }
    }

    /**
     * Invalidate (and close) every cached {@link FileChannel} whose file lives under {@code dirPath}.
     * Used on directory close / index removal so deleted-index FDs do not pin unlinked inodes and
     * cannot serve a later path reuse. Linear scan over the cached keys (bounded by the cache's max
     * size); invalidation is rare relative to reads.
     *
     * @param dirPath the directory whose files' cached channels should be dropped
     */
    public static void invalidateFileChannelsByPrefix(Path dirPath) {
        com.github.benmanes.caffeine.cache.Cache<String, FileChannel> local = fileChannelCache;
        if (local == null) {
            return;
        }
        // Reuse the single key builder so the "dio:" prefix + normalization can never drift from the
        // producer/consumer key format.
        String prefix = fileChannelCacheKey(dirPath);
        for (String key : local.asMap().keySet()) {
            // Match the directory prefix followed by the path separator (or exact), so e.g.
            // ".../index" does not spuriously match ".../index2".
            if (key.equals(prefix) || key.startsWith(prefix + java.io.File.separator)) {
                local.invalidate(key);
            }
        }
    }

    /**
     * Validates that the index is not an S3 vector index.
     * S3 vector indices are not compatible with cryptofs encryption.
     *
     * @param indexSettings the index settings to validate
     * @throws IllegalArgumentException if the index uses S3 vector engine
     */
    private void validateNotS3VectorIndex(IndexSettings indexSettings) {
        if (indexSettings.getIndexMetadata() == null || indexSettings.getIndexMetadata().mapping() == null) {
            return;
        }
        Map<String, Object> mapping = indexSettings.getIndexMetadata().mapping().getSourceAsMap();
        if (mapping != null) {
            validateMappingRecursive(mapping);
        }
    }

    /**
     * Recursively validates mapping structure to detect s3vector engine.
     *
     * @param map the mapping structure to validate
     * @throws IllegalArgumentException if s3vector engine is found
     */
    @SuppressWarnings("unchecked")
    void validateMappingRecursive(Map<String, Object> map) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                Map<String, Object> child = (Map<String, Object>) value;
                if ("method".equals(entry.getKey()) && "s3vector".equals(child.get("engine"))) {
                    throw new IllegalArgumentException("S3 vector indices (engine=s3vector) are not compatible with cryptofs store type.");
                }
                validateMappingRecursive(child);
            }
        }
    }
}
