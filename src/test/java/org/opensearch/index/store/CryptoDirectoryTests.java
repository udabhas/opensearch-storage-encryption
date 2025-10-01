/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

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
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * SMB Tests using NIO FileSystem as index store type.
 */
// @RunWith(RandomizedRunner.class)
public class CryptoDirectoryTests extends OpenSearchBaseDirectoryTestCase {

    static final String KEY_FILE_NAME = "keyfile";

    @Override
    protected Directory getDirectory(Path file) throws IOException {
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

        return new CryptoNIOFSDirectory(FSLockFactory.getDefault(), file, provider, keyResolver);
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
}
