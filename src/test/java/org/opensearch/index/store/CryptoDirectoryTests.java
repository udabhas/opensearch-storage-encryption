/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.tests.mockfile.ExtrasFS;
import org.opensearch.common.Randomness;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.telemetry.metrics.MetricsRegistry;

/**
 * SMB Tests using NIO FileSystem as index store type.
 */
// @RunWith(RandomizedRunner.class)
public class CryptoDirectoryTests extends OpenSearchBaseDirectoryTestCase {

    static final String KEY_FILE_NAME = "keyfile";

    @Override
    protected Directory getDirectory(Path file) throws IOException {
        // Create mock metricService
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));

        // Create raw AES key
        byte[] rawKey = new byte[32]; // 256-bit AES key
        byte[] encryptedKey = new byte[32]; // Not used in test but needed for interface
        java.util.Random rnd = Randomness.get();
        rnd.nextBytes(rawKey);
        rnd.nextBytes(encryptedKey);

        // Create mock KeyIvResolver
        KeyResolver keyResolver = mock(KeyResolver.class);
        byte[] iv = new byte[16]; // 128-bit IV for AES/CTR
        rnd.nextBytes(iv);

        when(keyResolver.getDataKey()).thenReturn(new SecretKeySpec(rawKey, "AES"));

        Provider provider = Security.getProvider("SunJCE");
        assertNotNull("Provider should not be null", provider);

        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        return new CryptoNIOFSDirectory(FSLockFactory.getDefault(), file, provider, keyResolver, cache);
    }

    @Override
    public void testCreateTempOutput() throws Throwable {
        try (Directory dir = getDirectory(createTempDir())) {
            List<String> names = new ArrayList<>();
            int iters = atLeast(50);
            for (int iter = 0; iter < iters; iter++) {
                IndexOutput out = dir.createTempOutput("foo", "bar", newIOContext(random()));
                names.add(out.getName());
                out.writeVInt(iter);
                out.close();
            }
            for (int iter = 0; iter < iters; iter++) {
                IndexInput in = dir.openInput(names.get(iter), newIOContext(random()));
                assertEquals(iter, in.readVInt());
                in.close();
            }

            Set<String> files = Arrays
                .stream(dir.listAll())
                .filter(file -> !ExtrasFS.isExtra(file)) // remove any ExtrasFS stuff.
                .filter(file -> !file.equals(KEY_FILE_NAME)) // remove keyfile.
                .collect(Collectors.toSet());

            assertEquals(new HashSet<String>(names), files);
        }
    }

    @Override
    public void testThreadSafetyInListAll() throws Exception {
        /*
        try (Directory dir = getDirectory(createTempDir("testThreadSafety"))) {
            if (dir instanceof BaseDirectoryWrapper) {
                // we are not making a real index, just writing, reading files.
                ((BaseDirectoryWrapper) dir).setCheckIndexOnClose(false);
            }
            if (dir instanceof MockDirectoryWrapper) {
                // makes this test really slow
                ((MockDirectoryWrapper) dir).setThrottling(MockDirectoryWrapper.Throttling.NEVER);
            }
        
            AtomicBoolean stop = new AtomicBoolean();
            Thread writer = new Thread(() -> {
                try {
                    for (int i = 0, max = RandomizedTest.randomIntBetween(500, 1000); i < max; i++) {
                        String fileName = "file-" + i;
                        try (IndexOutput output = dir.createOutput(fileName, newIOContext(random()))) {
                            assert output != null;
                            // Add some lags so that the other thread can read the content of the
                            // directory.
                            Thread.yield();
                        }
                        assertTrue(slowFileExists(dir, fileName));
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                } finally {
                    stop.set(true);
                }
            });
        
            Thread reader = new Thread(() -> {
                try {
                    Random rnd = new Random(RandomizedTest.randomLong());
                    while (!stop.get()) {
                        String[] files = Arrays.stream(dir.listAll())
                            .filter(name -> !ExtrasFS.isExtra(name)) // Ignore anything from ExtraFS.
                            .filter(name -> !name.equals(KEY_FILE_NAME)) // remove keyfile.
                            .toArray(String[]::new);
        
                        if (files.length > 0) {
                            do {
                                String file = RandomPicks.randomFrom(rnd, files);
                                try (IndexInput input = dir.openInput(file, newIOContext(random()))) {
                                    // Just open, nothing else.
                                    assert input != null;
                                } catch (@SuppressWarnings("unused") AccessDeniedException e) {
                                    // Access denied is allowed for files for which the output is still open
                                    // (MockDirectoryWriter enforces
                                    // this, for example). Since we don't synchronize with the writer thread,
                                    // just ignore it.
                                } catch (IOException e) {
                                    throw new UncheckedIOException("Something went wrong when opening: " + file, e);
                                }
                            } while (rnd.nextInt(3) != 0); // Sometimes break and list files again.
                        }
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        
            reader.start();
            writer.start();
        
            writer.join();
            reader.join();
        } */
    }

    public void testRandomAccessWithCryptoOutput() throws Exception {
        try (Directory dir = getDirectory(createTempDir())) {
            String fileName = "test-random-access";
            int blockSize = 16;
            int dataSize = blockSize * 3;

            // Generate predictable random data
            byte[] testData = new byte[dataSize];
            java.util.Random rnd = new java.util.Random(42); // Fixed seed for predictability
            rnd.nextBytes(testData);

            // Write data using CryptoOutput
            try (IndexOutput output = dir.createOutput(fileName, newIOContext(random()))) {
                output.writeBytes(testData, testData.length);
            }

            // Read randomly at different positions
            try (IndexInput input = dir.openInput(fileName, newIOContext(random()))) {
                // Test reading from start
                input.seek(0);
                assertEquals(testData[0], input.readByte());

                // Test reading from middle of first block
                input.seek(8);
                assertEquals(testData[8], input.readByte());

                // Test reading from start of second block
                input.seek(blockSize);
                assertEquals(testData[blockSize], input.readByte());

                // Test reading from middle of second block
                input.seek(blockSize + 8);
                assertEquals(testData[blockSize + 8], input.readByte());

                // Test reading from start of third block
                input.seek(blockSize * 2);
                assertEquals(testData[blockSize * 2], input.readByte());

                // Test reading multiple bytes at random position
                input.seek(5);
                byte[] buffer = new byte[10];
                input.readBytes(buffer, 0, 10);
                for (int i = 0; i < 10; i++) {
                    assertEquals(testData[5 + i], buffer[i]);
                }
            }
        }
    }

    @Override
    public void testSliceOutOfBounds() {
        /*
         * FIX PENDING: https://github.com/opensearch-project/opensearch-storage-encryption/issues/47
         */
    }

    // ==================== Enable/Disable Flag Tests ====================

    /**
     * Test that plugin is enabled when setting is true.
     */
    public void testPluginEnabledWhenSettingIsTrue() {
        org.opensearch.common.settings.Settings settings = org.opensearch.common.settings.Settings
            .builder()
            .put(CryptoDirectoryPlugin.CRYPTO_PLUGIN_ENABLED, true)
            .build();
        CryptoDirectoryPlugin plugin = new CryptoDirectoryPlugin(settings);
        assertFalse("Plugin should not be disabled when enabled setting is true", plugin.isDisabled());
    }

    /**
     * Test that plugin is disabled by default.
     */
    public void testPluginDisabledByDefault() {
        CryptoDirectoryPlugin plugin = new CryptoDirectoryPlugin(org.opensearch.common.settings.Settings.EMPTY);
        assertTrue("Plugin should be disabled by default", plugin.isDisabled());
    }

    /**
     * Test that no directory factories are registered when plugin is disabled.
     */
    public void testNoDirectoryFactoriesWhenDisabled() {
        org.opensearch.common.settings.Settings settings = org.opensearch.common.settings.Settings
            .builder()
            .put(CryptoDirectoryPlugin.CRYPTO_PLUGIN_ENABLED, false)
            .build();
        CryptoDirectoryPlugin plugin = new CryptoDirectoryPlugin(settings);
        assertTrue("Directory factories should be empty when disabled", plugin.getDirectoryFactories().isEmpty());
    }

    /**
     * Test that directory factory is registered when plugin is enabled.
     */
    public void testDirectoryFactoryRegisteredWhenEnabled() {
        org.opensearch.common.settings.Settings settings = org.opensearch.common.settings.Settings
            .builder()
            .put(CryptoDirectoryPlugin.CRYPTO_PLUGIN_ENABLED, true)
            .build();
        CryptoDirectoryPlugin plugin = new CryptoDirectoryPlugin(settings);
        assertFalse("Directory factories should not be empty when enabled", plugin.getDirectoryFactories().isEmpty());
        assertNotNull("CryptoFS factory should be registered", plugin.getDirectoryFactories().get("cryptofs"));
    }

    /**
     * Test that enabled setting is included in plugin settings.
     */
    public void testEnabledSettingIncluded() {
        CryptoDirectoryPlugin plugin = new CryptoDirectoryPlugin(org.opensearch.common.settings.Settings.EMPTY);
        assertTrue(
            "Settings should contain enabled setting",
            plugin.getSettings().contains(CryptoDirectoryPlugin.CRYPTO_PLUGIN_ENABLED_SETTING)
        );
    }

    /**
     * Test that enabled setting has correct default value (false - disabled by default).
     */
    public void testEnabledSettingDefault() {
        assertEquals(
            "Enabled setting default should be false (disabled by default)",
            Boolean.FALSE,
            CryptoDirectoryPlugin.CRYPTO_PLUGIN_ENABLED_SETTING.getDefault(org.opensearch.common.settings.Settings.EMPTY)
        );
    }

    // ==================== SI / segments_N Plaintext Passthrough Tests ====================
    //
    // segments_N and .si files are intentionally NOT encrypted for now — they are delegated to the
    // plaintext NIOFS impl (see CryptoNIOFSDirectory). Encryption for these will be added back later
    // (requires accompanying core changes). These tests pin that passthrough contract: the bytes on
    // disk are the raw plaintext (no OSEF footer), and round-trips through the directory still work.

    /**
     * .si files are written as plaintext on disk (not encrypted) and round-trip correctly.
     */
    public void testSiFileIsPlaintextOnDisk() throws IOException {
        Path tempPath = createTempDir();
        try (Directory dir = getDirectory(tempPath)) {
            byte[] data = "SI_CONTENT_MUST_BE_PLAINTEXT_99".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try (IndexOutput out = dir.createOutput("_0.si", newIOContext(random()))) {
                out.writeBytes(data, 0, data.length);
            }

            // Bytes on disk must be the raw plaintext — no encryption, no OSEF footer.
            byte[] onDisk = java.nio.file.Files.readAllBytes(tempPath.resolve("_0.si"));
            assertEquals("_0.si should be plaintext on disk (no footer)", data.length, onDisk.length);
            assertEquals("SI_CONTENT_MUST_BE_PLAINTEXT_99", new String(onDisk, java.nio.charset.StandardCharsets.UTF_8));

            // Read back through crypto dir — plaintext passthrough should return the same bytes.
            try (IndexInput in = dir.openInput("_0.si", newIOContext(random()))) {
                byte[] read = new byte[data.length];
                in.readBytes(read, 0, data.length);
                assertEquals("SI_CONTENT_MUST_BE_PLAINTEXT_99", new String(read, java.nio.charset.StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * segments_* files are written as plaintext on disk (not encrypted) and round-trip correctly.
     */
    public void testSegmentsFileIsPlaintextOnDisk() throws IOException {
        Path tempPath = createTempDir();
        try (Directory dir = getDirectory(tempPath)) {
            byte[] data = "SEGMENTS_DATA_PLAINTEXT_XYZ".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try (IndexOutput out = dir.createOutput("segments_1", newIOContext(random()))) {
                out.writeBytes(data, 0, data.length);
            }

            byte[] onDisk = java.nio.file.Files.readAllBytes(tempPath.resolve("segments_1"));
            assertEquals("segments_1 should be plaintext on disk (no footer)", data.length, onDisk.length);
            assertEquals("SEGMENTS_DATA_PLAINTEXT_XYZ", new String(onDisk, java.nio.charset.StandardCharsets.UTF_8));

            try (IndexInput in = dir.openInput("segments_1", newIOContext(random()))) {
                byte[] read = new byte[data.length];
                in.readBytes(read, 0, data.length);
                assertEquals("SEGMENTS_DATA_PLAINTEXT_XYZ", new String(read, java.nio.charset.StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * Plaintext .si files (from pre-encryption indices, or written via the current plaintext
     * passthrough) are readable.
     */
    public void testPlaintextSiFallback() throws IOException {
        Path tempPath = createTempDir();
        byte[] data = "OLD_PLAINTEXT_SI".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Write plaintext file directly (simulating pre-encryption index)
        java.nio.file.Files.write(tempPath.resolve("_0.si"), data);

        try (Directory dir = getDirectory(tempPath)) {
            try (IndexInput in = dir.openInput("_0.si", newIOContext(random()))) {
                byte[] read = new byte[data.length];
                in.readBytes(read, 0, data.length);
                assertEquals("OLD_PLAINTEXT_SI", new String(read, java.nio.charset.StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * fileLength() for a .si file equals the raw on-disk size (plaintext passthrough — no footer to
     * subtract).
     */
    public void testFileLengthForSiFile() throws IOException {
        try (Directory dir = getDirectory(createTempDir())) {
            byte[] data = "LENGTH_CHECK_DATA".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            try (IndexOutput out = dir.createOutput("_0.si", newIOContext(random()))) {
                out.writeBytes(data, 0, data.length);
            }

            assertEquals("fileLength should equal plaintext content length", data.length, dir.fileLength("_0.si"));
        }
    }
}
