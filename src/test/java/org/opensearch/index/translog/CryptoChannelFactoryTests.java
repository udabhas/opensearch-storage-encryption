/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.key.DefaultKeyResolver;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.key.MasterKeyHealthMonitor;
import org.opensearch.index.store.key.NodeLevelKeyCache;
import org.opensearch.index.store.key.ShardCacheKey;
import org.opensearch.index.store.key.ShardKeyResolverRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Tests for {@link CryptoChannelFactory}, focused on wrapper-tracking cleanup: the per-path wrapper-tracking map must
 * NOT grow unbounded — closing a translog channel must drop its tracking entry, otherwise a long-lived
 * shard rolling many generations accumulates one stale (closed channel + frame manager) entry per file
 * for its entire lifetime.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class CryptoChannelFactoryTests extends OpenSearchTestCase {

    private Path tempDir;
    private KeyResolver keyResolver;
    private String testIndexUuid;

    @SuppressForbidden(reason = "Test needs to register resolver in ShardKeyResolverRegistry")
    private void registerResolver(String indexUuid, int shardId, KeyResolver resolver) throws Exception {
        Field resolverCacheField = ShardKeyResolverRegistry.class.getDeclaredField("resolverCache");
        resolverCacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        ConcurrentMap<ShardCacheKey, KeyResolver> resolverCache = (ConcurrentMap<ShardCacheKey, KeyResolver>) resolverCacheField.get(null);
        resolverCache.put(new ShardCacheKey(indexUuid, shardId, "test-index"), resolver);
    }

    @Override
    @SuppressForbidden(reason = "Creating temp directory for test purposes")
    public void setUp() throws Exception {
        super.setUp();
        tempDir = Files.createTempDirectory("crypto-channel-factory-test");
        ShardKeyResolverRegistry.clearCache();

        Settings nodeSettings = Settings.builder().put("node.store.crypto.key_refresh_interval", "5m").build();

        Client mockClient = mock(Client.class);
        ClusterService mockClusterService = mock(ClusterService.class);
        AdminClient mockAdminClient = mock(AdminClient.class);
        IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
        @SuppressWarnings("unchecked")
        ActionFuture<AcknowledgedResponse> mockFuture = (ActionFuture<AcknowledgedResponse>) mock(ActionFuture.class);
        when(mockClient.admin()).thenReturn(mockAdminClient);
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);
        when(mockIndicesAdminClient.updateSettings(any())).thenReturn(mockFuture);
        when(mockFuture.actionGet()).thenReturn(mock(AcknowledgedResponse.class));

        org.opensearch.index.store.metrics.CryptoMetricsService.initialize(mock(org.opensearch.telemetry.metrics.MetricsRegistry.class));
        MasterKeyHealthMonitor.initialize(nodeSettings, mockClient, mockClusterService);
        NodeLevelKeyCache.initialize(nodeSettings, MasterKeyHealthMonitor.getInstance());

        Provider cryptoProvider = Security.getProvider("SunJCE");
        MasterKeyProvider keyProvider = new MasterKeyProvider() {
            @Override
            public Map<String, String> getEncryptionContext() {
                return Collections.singletonMap("test-key", "test-value");
            }

            @Override
            public byte[] decryptKey(byte[] encryptedKey) {
                return new byte[32];
            }

            @Override
            public String getKeyId() {
                return "test-key-id";
            }

            @Override
            public org.opensearch.common.crypto.DataKeyPair generateDataPair() {
                return new org.opensearch.common.crypto.DataKeyPair(new byte[32], new byte[32]);
            }

            @Override
            public void close() {}
        };

        testIndexUuid = "test-index-uuid-" + System.nanoTime();
        org.apache.lucene.store.Directory directory = new org.apache.lucene.store.NIOFSDirectory(tempDir);
        keyResolver = new DefaultKeyResolver(testIndexUuid, "test-index", directory, cryptoProvider, keyProvider, 0);
        registerResolver(testIndexUuid, 0, keyResolver);
    }

    @Override
    public void tearDown() throws Exception {
        MasterKeyHealthMonitor.reset();
        NodeLevelKeyCache.reset();
        super.tearDown();
    }

    /** A fresh writer is tracked while open, and the entry is dropped once the channel is closed. */
    public void testWrapperTrackingEntryDroppedOnClose() throws Exception {
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, "test-uuid");
        Path path = tempDir.resolve("translog-1.tlog");

        assertEquals("no wrappers tracked before any open", 0, factory.trackedWrapperCount());

        FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ);
        assertEquals("open .tlog must be tracked", 1, factory.trackedWrapperCount());

        ch.close();
        assertEquals("closing the channel must drop the tracking entry", 0, factory.trackedWrapperCount());
    }

    /** The map stays bounded across many generations — no per-generation entry leak occurs. */
    public void testTrackingMapDoesNotGrowAcrossGenerations() throws Exception {
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, "test-uuid");

        for (int gen = 1; gen <= 50; gen++) {
            Path path = tempDir.resolve("translog-" + gen + ".tlog");
            try (FileChannel ch = factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ)) {
                assertEquals("exactly the current open generation is tracked", 1, factory.trackedWrapperCount());
            }
            assertEquals("each generation's entry is released on close", 0, factory.trackedWrapperCount());
        }

        assertEquals("no stale entries after rolling 50 generations", 0, factory.trackedWrapperCount());
    }

    /** A non-.tlog file (e.g. a checkpoint) is passed through unencrypted and never enters the map. */
    public void testNonTlogFileNotTracked() throws Exception {
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, "test-uuid");
        Path ckp = tempDir.resolve("translog-1.ckp");
        try (FileChannel ch = factory.open(ckp, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ)) {
            assertEquals("plaintext .ckp pass-through is not tracked", 0, factory.trackedWrapperCount());
        }
        assertEquals(0, factory.trackedWrapperCount());
    }
}
