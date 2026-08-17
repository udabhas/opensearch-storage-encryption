/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.hybrid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.Random;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.KeyResolver;

/**
 * Unit tests for HybridCryptoDirectory routing logic.
 */
public class HybridCryptoDirectoryTests {

    private Path tempDir;
    private KeyResolver keyResolver;
    private Provider provider;
    private EncryptionMetadataCache encryptionMetadataCache;
    private LockFactory lockFactory;
    private BufferPoolDirectory bufferPoolDirectory;
    private Set<String> nioExtensions;

    @Before
    public void setUp() throws Exception {
        tempDir = Files.createTempDirectory("hybrid-test");

        // Create mock KeyResolver
        keyResolver = mock(KeyResolver.class);
        byte[] rawKey = new byte[32];
        new Random().nextBytes(rawKey);
        when(keyResolver.getDataKey()).thenReturn(new SecretKeySpec(rawKey, "AES"));

        provider = Security.getProvider("SunJCE");
        assertNotNull("Provider should not be null", provider);

        encryptionMetadataCache = new EncryptionMetadataCache();
        lockFactory = FSLockFactory.getDefault();

        // Mock CryptoDirectIODirectory
        bufferPoolDirectory = mock(BufferPoolDirectory.class);
        when(bufferPoolDirectory.getDirectory()).thenReturn(tempDir);

        // Default NIO extensions (metadata/small files)
        nioExtensions = Set.of("si", "cfe", "fnm", "fdx", "fdt", "pos", "pay", "nvm", "dvm", "tvx", "tvd", "liv", "dii", "vem");
    }

    @After
    public void tearDown() throws Exception {
        if (tempDir != null && Files.exists(tempDir)) {
            Files.walk(tempDir).sorted((a, b) -> -a.compareTo(b)).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    // ignore
                }
            });
        }
    }

    @Test
    public void testCreateOutputRoutesToNIOForDataFiles() throws Exception {
        // Write routing is intentionally NIO-only: createOutput delegates to super (CryptoNIOFSDirectory)
        // for ALL files, so BufferPool never sees a write. The extension-based BufferPool write route is
        // commented out in HybridCryptoDirectory.createOutput; reads still route to BufferPool via openInput
        // (see testOpenInputRoutesToDirectIOForDataFiles). .tim is a data extension but is no longer
        // write-routed to BufferPool.
        try (
            HybridCryptoDirectory hybridDir = new HybridCryptoDirectory(
                lockFactory,
                bufferPoolDirectory,
                provider,
                keyResolver,
                encryptionMetadataCache,
                nioExtensions
            )
        ) {
            IndexOutput output = hybridDir.createOutput("test.tim", IOContext.DEFAULT);
            assertNotNull(output);
            output.close();

            verify(bufferPoolDirectory, never()).createOutput(eq("test.tim"), any(IOContext.class));
            assertTrue(Files.exists(tempDir.resolve("test.tim")));
        }
    }

    @Test
    public void testCreateOutputRoutesToNIOForMetadataFiles() throws Exception {
        HybridCryptoDirectory hybridDir = spy(
            new HybridCryptoDirectory(lockFactory, bufferPoolDirectory, provider, keyResolver, encryptionMetadataCache, nioExtensions)
        );

        try {
            // .si IS in nioExtensions, should route to NIO (super)
            // This will create an actual file via CryptoNIOFSDirectory
            IndexOutput output = hybridDir.createOutput("test.si", IOContext.DEFAULT);
            assertNotNull(output);
            output.close();

            // Verify DirectIO was NOT called
            verify(bufferPoolDirectory, never()).createOutput(eq("test.si"), any(IOContext.class));

            // Verify file was created
            assertTrue(Files.exists(tempDir.resolve("test.si")));
        } finally {
            hybridDir.close();
        }
    }

    @Test
    public void testOpenInputRoutesToDirectIOForDataFiles() throws Exception {
        try (
            HybridCryptoDirectory hybridDir = new HybridCryptoDirectory(
                lockFactory,
                bufferPoolDirectory,
                provider,
                keyResolver,
                encryptionMetadataCache,
                nioExtensions
            )
        ) {
            // Mock the openInput for DirectIO
            IndexInput mockInput = mock(IndexInput.class);
            when(bufferPoolDirectory.openInput(eq("test.doc"), any(IOContext.class))).thenReturn(mockInput);

            // Create dummy file so ensureCanRead passes
            Files.createFile(tempDir.resolve("test.doc"));

            // .doc is NOT in nioExtensions, should route to DirectIO
            IndexInput input = hybridDir.openInput("test.doc", IOContext.DEFAULT);
            assertEquals(mockInput, input);
            verify(bufferPoolDirectory).openInput(eq("test.doc"), any(IOContext.class));
        }
    }

    @Test
    public void testOpenInputRoutesToNIOForMetadataFiles() throws Exception {
        HybridCryptoDirectory hybridDir = spy(
            new HybridCryptoDirectory(lockFactory, bufferPoolDirectory, provider, keyResolver, encryptionMetadataCache, nioExtensions)
        );

        try {
            // First create a file via NIO
            IndexOutput output = hybridDir.createOutput("test.fnm", IOContext.DEFAULT);
            output.writeByte((byte) 42);
            output.close();

            // .fnm IS in nioExtensions, should route to NIO (super)
            IndexInput input = hybridDir.openInput("test.fnm", IOContext.DEFAULT);
            assertNotNull(input);
            input.close();

            // Verify DirectIO was NOT called
            verify(bufferPoolDirectory, never()).openInput(eq("test.fnm"), any(IOContext.class));
        } finally {
            hybridDir.close();
        }
    }

    @Test
    public void testDeleteFileDoesNotRouteToDirectIOForDataFiles() throws Exception {
        HybridCryptoDirectory hybridDir = spy(
            new HybridCryptoDirectory(lockFactory, bufferPoolDirectory, provider, keyResolver, encryptionMetadataCache, nioExtensions)
        );

        try {
            // Create a file first
            Files.createFile(tempDir.resolve("test.cfs"));

            // .cfs is NOT in nioExtensions, but deleteFile now routes ALL files through NIOFS (super) —
            // never the buffer-pool directory.
            hybridDir.deleteFile("test.cfs");

            // Verify the buffer-pool (DirectIO) path was NOT used
            verify(bufferPoolDirectory, never()).deleteFile("test.cfs");

            // Verify the file was actually deleted via NIOFS (not a no-op)
            assertTrue(!Files.exists(tempDir.resolve("test.cfs")));
        } finally {
            hybridDir.close();
        }
    }

    @Test
    public void testDeleteFileRoutesToNIOForMetadataFiles() throws Exception {
        HybridCryptoDirectory hybridDir = spy(
            new HybridCryptoDirectory(lockFactory, bufferPoolDirectory, provider, keyResolver, encryptionMetadataCache, nioExtensions)
        );

        try {
            // Create a file first
            Files.createFile(tempDir.resolve("test.dvm"));

            // .dvm IS in nioExtensions, should route to NIO (super)
            hybridDir.deleteFile("test.dvm");

            // Verify DirectIO was NOT called
            verify(bufferPoolDirectory, never()).deleteFile("test.dvm");

            // Verify file was deleted
            assertTrue(!Files.exists(tempDir.resolve("test.dvm")));
        } finally {
            hybridDir.close();
        }
    }

    @Test
    public void testCreateOutputRoutesToNIOForAllExtensions() throws Exception {
        // Writes are NIO-only regardless of extension (the BufferPool write route is commented out in
        // HybridCryptoDirectory.createOutput). Read routing by extension is unchanged and covered by the
        // openInput tests.
        try (
            HybridCryptoDirectory hybridDir = new HybridCryptoDirectory(
                lockFactory,
                bufferPoolDirectory,
                provider,
                keyResolver,
                encryptionMetadataCache,
                nioExtensions
            )
        ) {
            // data extensions that previously write-routed to BufferPool, plus an unknown extension
            String[] extensions = { "tim", "doc", "dvd", "nvd", "cfs", "kdd", "tip", "tmd", "xyz" };
            for (String ext : extensions) {
                String fileName = "test." + ext;
                IndexOutput output = hybridDir.createOutput(fileName, IOContext.DEFAULT);
                assertNotNull(output);
                output.close();
                verify(bufferPoolDirectory, never()).createOutput(eq(fileName), any(IOContext.class));
                assertTrue("write for ." + ext + " should land on disk via NIO", Files.exists(tempDir.resolve(fileName)));
            }
        }
    }
}
