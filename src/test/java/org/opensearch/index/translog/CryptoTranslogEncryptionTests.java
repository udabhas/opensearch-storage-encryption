/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
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

/**
 * Verify that translog data encryption actually works.
 */
public class CryptoTranslogEncryptionTests extends OpenSearchTestCase {

    private static final Logger logger = LogManager.getLogger(CryptoTranslogEncryptionTests.class);

    private Path tempDir;
    private KeyResolver keyResolver;
    private MasterKeyProvider keyProvider;
    private String testIndexUuid;

    /**
     * Helper method to register the resolver in the ShardKeyResolverRegistry
     */
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
        tempDir = Files.createTempDirectory("crypto-translog-encryption-test");

        // Clear the ShardKeyResolverRegistry cache before each test
        ShardKeyResolverRegistry.clearCache();

        // Initialize NodeLevelKeyCache with test settings
        Settings nodeSettings = Settings
            .builder()
            .put("node.store.crypto.key_refresh_interval", "5m") // 5 minutes for tests
            .build();

        // Create mock Client and ClusterService for testing
        Client mockClient = mock(Client.class);
        ClusterService mockClusterService = mock(ClusterService.class);

        // Setup mock Client chain for block operations
        AdminClient mockAdminClient = mock(AdminClient.class);
        IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
        @SuppressWarnings("unchecked")
        ActionFuture<AcknowledgedResponse> mockFuture = (ActionFuture<AcknowledgedResponse>) mock(ActionFuture.class);

        when(mockClient.admin()).thenReturn(mockAdminClient);
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);
        when(mockIndicesAdminClient.updateSettings(any())).thenReturn(mockFuture);
        when(mockFuture.actionGet()).thenReturn(mock(AcknowledgedResponse.class));

        MasterKeyHealthMonitor.initialize(nodeSettings, mockClient, mockClusterService);
        NodeLevelKeyCache.initialize(nodeSettings, MasterKeyHealthMonitor.getInstance());

        Provider cryptoProvider = Security.getProvider("SunJCE");

        // Create a mock key provider for testing
        keyProvider = new MasterKeyProvider() {
            @Override
            public java.util.Map<String, String> getEncryptionContext() {
                return java.util.Collections.singletonMap("test-key", "test-value");
            }

            @Override
            public byte[] decryptKey(byte[] encryptedKey) {
                return new byte[32]; // 256-bit key
            }

            @Override
            public String getKeyId() {
                return "test-key-id";
            }

            @Override
            public org.opensearch.common.crypto.DataKeyPair generateDataPair() {
                byte[] rawKey = new byte[32];
                byte[] encryptedKey = new byte[32];
                return new org.opensearch.common.crypto.DataKeyPair(rawKey, encryptedKey);
            }

            @Override
            public void close() {
                // No resources to close
            }
        };

        // Use a test index UUID
        testIndexUuid = "test-index-uuid-" + System.currentTimeMillis();
        org.apache.lucene.store.Directory directory = new org.apache.lucene.store.NIOFSDirectory(tempDir);
        // keyResolver = new DefaultKeyResolver(directory, cryptoProvider, keyProvider);
        keyResolver = new DefaultKeyResolver(testIndexUuid, "test-index", directory, cryptoProvider, keyProvider, 0);

        // Register the resolver with ShardKeyResolverRegistry so cache can find it
        registerResolver(testIndexUuid, 0, keyResolver);
    }

    @Override
    public void tearDown() throws Exception {
        // Reset singletons to prevent test pollution
        MasterKeyHealthMonitor.reset();
        NodeLevelKeyCache.reset();
        // Clear the ShardKeyResolverRegistry cache
        ShardKeyResolverRegistry.clearCache();
        super.tearDown();
    }

    public void testTranslogDataIsActuallyEncrypted() throws IOException {
        String testTranslogUUID = "test-encryption-uuid";
        CryptoChannelFactory channelFactory = new CryptoChannelFactory(keyResolver, testTranslogUUID);

        Path translogPath = tempDir.resolve("test-encryption.tlog");

        // Test data that should be encrypted
        String sensitiveData =
            "{\"@timestamp\": 894069207, \"clientip\":\"192.168.1.1\", \"request\": \"GET /secret/data HTTP/1.1\", \"status\": 200}";
        byte[] testData = sensitiveData.getBytes(StandardCharsets.UTF_8);

        // Write header + data using our crypto channel (with READ permission for round-trip verification)
        try (
            FileChannel cryptoChannel = channelFactory
                .open(translogPath, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)
        ) {

            // First write the header
            TranslogHeader header = new TranslogHeader(testTranslogUUID, 1L);
            header.write(cryptoChannel, false);
            int headerSize = header.sizeInBytes();

            logger.info("Header size: {} bytes", headerSize);

            // Now write data that should be encrypted (beyond header)
            ByteBuffer dataBuffer = ByteBuffer.wrap(testData);
            int bytesWritten = cryptoChannel.write(dataBuffer, headerSize);

            assertEquals("Should write all test data", testData.length, bytesWritten);
        }

        // CRITICAL: Read raw file content and verify data is encrypted (NOT readable)
        byte[] fileContent = Files.readAllBytes(translogPath);
        String fileContentString = new String(fileContent, StandardCharsets.UTF_8);
        String fileContentISO = new String(fileContent, StandardCharsets.ISO_8859_1);

        logger.info("File size: {} bytes", fileContent.length);
        logger.info("File content UTF-8 (first 200 chars): {}", fileContentString.substring(0, Math.min(200, fileContentString.length())));
        logger.info("File content ISO-8859-1 (first 200 chars): {}", fileContentISO.substring(0, Math.min(200, fileContentISO.length())));
        logger.info("UUID in UTF-8: {}", fileContentString.contains(testTranslogUUID));
        logger.info("UUID in ISO-8859-1: {}", fileContentISO.contains(testTranslogUUID));

        // Debug: print first 53 bytes (header) as hex
        StringBuilder hexHeader = new StringBuilder();
        for (int i = 0; i < Math.min(53, fileContent.length); i++) {
            hexHeader.append(String.format("%02X ", fileContent[i]));
        }
        logger.info("Header bytes (hex): {}", hexHeader.toString());

        assertFalse("Sensitive data found in plain text! File content: " + fileContentString, fileContentString.contains("192.168.1.1"));

        assertFalse("Sensitive data found in plain text! File content: " + fileContentString, fileContentString.contains("/secret/data"));

        assertFalse("JSON structure found in plain text! File content: " + fileContentString, fileContentString.contains("\"clientip\""));

        // Verify header is still readable (should be unencrypted)
        assertTrue(
            "Header should contain translog UUID",
            fileContentString.contains(testTranslogUUID) || fileContentISO.contains(testTranslogUUID)
        );
    }

    /**
     * Verify read/write round trip works correctly.
     */
    public void testTranslogEncryptionDecryptionRoundTrip() throws IOException {
        String testTranslogUUID = "test-roundtrip-uuid";
        CryptoChannelFactory channelFactory = new CryptoChannelFactory(keyResolver, testTranslogUUID);

        Path translogPath = tempDir.resolve("test-roundtrip.tlog");

        String originalData = "{\"test\": \"sensitive document data that must be encrypted\"}";
        byte[] testData = originalData.getBytes(StandardCharsets.UTF_8);

        int headerSize;

        // Write data
        try (FileChannel writeChannel = channelFactory.open(translogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            // Write header
            TranslogHeader header = new TranslogHeader(testTranslogUUID, 1L);
            header.write(writeChannel, false);
            headerSize = header.sizeInBytes();

            // Write data beyond header
            ByteBuffer writeBuffer = ByteBuffer.wrap(testData);
            writeChannel.write(writeBuffer, headerSize);
        }

        // Read data back
        try (FileChannel readChannel = channelFactory.open(translogPath, StandardOpenOption.READ)) {
            // Skip header
            readChannel.position(headerSize);

            // Read encrypted data
            ByteBuffer readBuffer = ByteBuffer.allocate(testData.length);
            int bytesRead = readChannel.read(readBuffer);

            assertEquals("Should read same amount as written", testData.length, bytesRead);

            // Verify decrypted data matches original
            String decryptedData = new String(readBuffer.array(), StandardCharsets.UTF_8);
            assertEquals("Decrypted data should match original", originalData, decryptedData);
        }

        // Verify file content is still encrypted on disk
        byte[] rawFileContent = Files.readAllBytes(translogPath);
        String rawContent = new String(rawFileContent, StandardCharsets.UTF_8);

        assertFalse("Data should be encrypted on disk", rawContent.contains("sensitive document data"));
    }

    /**
     * Verifies sequential read from position 0 with a large buffer only returns
     * header bytes first, then decrypted data on the next read.
     */
    public void testSequentialReadLimitsHeaderPassthrough() throws IOException {
        String uuid = "test-header-limit-uuid";
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        Path tlogPath = tempDir.resolve("test-header-limit.tlog");

        String testData = "{\"message\": \"test data for header limit verification\"}";
        byte[] dataBytes = testData.getBytes(StandardCharsets.UTF_8);
        int headerSize;

        try (FileChannel ch = factory.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ)) {
            TranslogHeader header = new TranslogHeader(uuid, 1L);
            header.write(ch, false);
            headerSize = header.sizeInBytes();
            ch.write(ByteBuffer.wrap(dataBytes), headerSize);
        }

        assertTrue("File should be larger than header+data due to GCM tag", Files.size(tlogPath) > headerSize + dataBytes.length);

        try (FileChannel ch = factory.open(tlogPath, StandardOpenOption.READ)) {
            ByteBuffer buf = ByteBuffer.allocate(8192);
            int firstRead = ch.read(buf);
            assertEquals("First sequential read should return exactly headerSize bytes", headerSize, firstRead);

            buf.clear();
            int secondRead = ch.read(buf);
            assertEquals("Second read should return original plaintext data length", dataBytes.length, secondRead);

            buf.flip();
            byte[] decrypted = new byte[secondRead];
            buf.get(decrypted);
            assertEquals("Decrypted data should match original", testData, new String(decrypted, StandardCharsets.UTF_8));
        }
    }

    /**
     * Verifies CryptoDecryptingInputStream produces decryptedSize < encryptedSize
     * (GCM tag stripped), confirming decryption actually happens.
     */
    public void testDecryptingInputStreamStripsGcmTag() throws IOException {
        String uuid = "test-decrypt-size-uuid";
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        Path tlogPath = tempDir.resolve("test-decrypt-size.tlog");

        byte[] dataBytes = "{\"key\": \"value\"}".getBytes(StandardCharsets.UTF_8);
        int headerSize;

        try (FileChannel ch = factory.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ)) {
            TranslogHeader header = new TranslogHeader(uuid, 1L);
            header.write(ch, false);
            headerSize = header.sizeInBytes();
            ch.write(ByteBuffer.wrap(dataBytes), headerSize);
        }

        long encryptedSize = Files.size(tlogPath);
        long decryptedSize = 0;
        try (CryptoDecryptingInputStream stream = new CryptoDecryptingInputStream(tlogPath, keyResolver, uuid)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = stream.read(buf)) != -1) decryptedSize += read;
        }

        assertEquals("Decrypted = header + plaintext", headerSize + dataBytes.length, (int) decryptedSize);
        assertEquals("Difference should be GCM tag (16 bytes)", 16, encryptedSize - decryptedSize);
    }

    /**
     * Header-only files (no data) should pass through with same size.
     */
    public void testHeaderOnlyFileUnchangedThroughDecryptingStream() throws IOException {
        String uuid = "test-header-only-uuid";
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        Path tlogPath = tempDir.resolve("test-header-only.tlog");

        try (FileChannel ch = factory.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ)) {
            new TranslogHeader(uuid, 1L).write(ch, false);
        }

        long fileSize = Files.size(tlogPath);
        long decryptedSize = 0;
        try (CryptoDecryptingInputStream stream = new CryptoDecryptingInputStream(tlogPath, keyResolver, uuid)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = stream.read(buf)) != -1) decryptedSize += read;
        }
        assertEquals("Header-only: decrypted size should equal file size", fileSize, decryptedSize);
    }

    /**
     * Plaintext translog file (simulating S3 download) is detected as plaintext
     * when decryption fails, and can be re-encrypted successfully.
     */
    public void testPlaintextFileDetectedAndReEncryptable() throws Exception {
        String uuid = "test-reencrypt-uuid";
        int headerSize = TranslogChunkManager.calculateTranslogHeaderSizeStatic(uuid);

        // Create plaintext translog (simulating S3 download after restore)
        Path tlogPath = tempDir.resolve("translog-5.tlog");
        byte[] header = createRawHeader(uuid, 1L);
        byte[] plainData = "{\"@timestamp\":\"2099-01-01\",\"msg\":\"test\"}".getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            ch.write(ByteBuffer.wrap(header));
            ch.write(ByteBuffer.wrap(plainData));
        }

        // Derive IV (same as TranslogChunkManager/reEncrypt logic)
        byte[] baseIV = org.opensearch.index.store.key.HkdfKeyDerivation.deriveTranslogBaseIV(
            keyResolver.getDataKey().getEncoded(), uuid
        );
        byte[] chunkIV = org.opensearch.index.store.cipher.AesCipherFactory.computeOffsetIVForAesGcmEncrypted(baseIV, 0);

        // Decrypt should FAIL on plaintext
        try {
            org.opensearch.index.store.cipher.AesGcmCipherFactory.decryptWithTag(keyResolver.getDataKey(), chunkIV, plainData);
            fail("Decryption of plaintext should throw");
        } catch (org.opensearch.index.store.cipher.AesGcmCipherFactory.JavaCryptoException expected) {}

        // Encrypt it (same as reEncryptDownloadedTranslogFiles)
        byte[] encrypted = org.opensearch.index.store.cipher.AesGcmCipherFactory.encryptWithTag(
            keyResolver.getDataKey(), chunkIV, plainData, plainData.length
        );
        try (FileChannel out = FileChannel.open(tlogPath, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            out.write(ByteBuffer.wrap(header));
            out.write(ByteBuffer.wrap(encrypted));
        }

        assertEquals("Re-encrypted file = header + data + 16B tag", headerSize + plainData.length + 16, (int) Files.size(tlogPath));

        // CryptoDecryptingInputStream should now read it correctly
        long streamSize = 0;
        try (CryptoDecryptingInputStream stream = new CryptoDecryptingInputStream(tlogPath, keyResolver, uuid)) {
            byte[] buf = new byte[8192];
            int read;
            while ((read = stream.read(buf)) != -1) streamSize += read;
        }
        assertEquals("After re-encrypt: stream returns header + plaintext", headerSize + plainData.length, (int) streamSize);
    }

    /**
     * Already-encrypted file is detected (decrypt succeeds) and should NOT be re-encrypted.
     */
    public void testAlreadyEncryptedFileDetectedByDecrypt() throws Exception {
        String uuid = "test-already-enc-uuid";
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, uuid);
        Path tlogPath = tempDir.resolve("translog-3.tlog");

        byte[] testData = "{\"already\":\"encrypted\"}".getBytes(StandardCharsets.UTF_8);
        int headerSize;
        try (FileChannel ch = factory.open(tlogPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.READ)) {
            TranslogHeader h = new TranslogHeader(uuid, 1L);
            h.write(ch, false);
            headerSize = h.sizeInBytes();
            ch.write(ByteBuffer.wrap(testData), headerSize);
        }

        // Read data portion from disk
        byte[] fileBytes = Files.readAllBytes(tlogPath);
        byte[] data = java.util.Arrays.copyOfRange(fileBytes, headerSize, fileBytes.length);

        byte[] baseIV = org.opensearch.index.store.key.HkdfKeyDerivation.deriveTranslogBaseIV(
            keyResolver.getDataKey().getEncoded(), uuid
        );
        byte[] chunkIV = org.opensearch.index.store.cipher.AesCipherFactory.computeOffsetIVForAesGcmEncrypted(baseIV, 0);

        // Decrypt should SUCCEED — file is already encrypted
        byte[] decrypted = org.opensearch.index.store.cipher.AesGcmCipherFactory.decryptWithTag(
            keyResolver.getDataKey(), chunkIV, data
        );
        assertEquals("Decrypted matches original", new String(testData, StandardCharsets.UTF_8), new String(decrypted, StandardCharsets.UTF_8));
    }

    private byte[] createRawHeader(String uuid, long primaryTerm) throws IOException {
        Path tmp = tempDir.resolve("tmp-header.tlog");
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            new TranslogHeader(uuid, primaryTerm).write(ch, false);
        }
        byte[] bytes = Files.readAllBytes(tmp);
        Files.delete(tmp);
        return bytes;
    }
}
