/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.hybrid;

import java.io.IOException;
import java.security.Provider;
import java.util.Set;

import org.apache.lucene.store.FileSwitchDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;

/**
 * Hybrid encrypted directory that routes file operations based on OpenSearch's
 * {@code INDEX_STORE_HYBRID_NIO_EXTENSIONS} setting.
 *
 * <p>Routing logic:
 * <ul>
 * <li><strong>Direct I/O</strong> ({@link BufferPoolDirectory}): Files NOT in nioExtensions
 *     (e.g., tim, doc, dvd, nvd, cfs) - large data files with block caching</li>
 * <li><strong>NIO</strong> ({@link CryptoNIOFSDirectory}): Files in nioExtensions
 *     (e.g., si, cfe, fnm, fdx, segments_N) - metadata and small files</li>
 * </ul>
 *
 * <p>Both directories share the same encryption keys and IV resolution.
 *
 * @opensearch.internal
 */
public class HybridCryptoDirectory extends CryptoNIOFSDirectory {
    private final BufferPoolDirectory bufferPoolDirectory;
    private final Set<String> nioExtensions;

    /**
     * Creates a new HybridCryptoDirectory that routes operations between NIO and Direct I/O.
     *
     * <p>The hybrid directory uses the provided CryptoDirectIODirectory for performance-critical
     * large files and falls back to NIO operations for smaller files and metadata.
     *
     * @param lockFactory the lock factory for coordinating access across both directories
     * @param delegate the CryptoDirectIODirectory to use for Direct I/O operations
     * @param provider the security provider for cryptographic operations
     * @param keyResolver resolver for encryption keys and initialization vectors (shared across both directories)
     * @throws IOException if either directory cannot be initialized
     */
    public HybridCryptoDirectory(
        LockFactory lockFactory,
        BufferPoolDirectory delegate,
        Provider provider,
        KeyResolver keyResolver,
        EncryptionMetadataCache encryptionMetadataCache,
        Set<String> nioExtensions
    )
        throws IOException {
        super(lockFactory, delegate.getDirectory(), provider, keyResolver, encryptionMetadataCache);
        this.bufferPoolDirectory = delegate;
        this.nioExtensions = nioExtensions;
    }

    /**
     * Determines if a file should be routed to Direct I/O + caching directory
     * based on its extension.
     *
     * @param extension the file extension
     * @return true if the file should use Direct I/O, false for NIO
     */
    private boolean delegeteBufferPool(String extension) {
        return !extension.isEmpty() && !nioExtensions.contains(extension);
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        String extension = FileSwitchDirectory.getExtension(name);

        ensureOpen();
        ensureCanRead(name);

        if (delegeteBufferPool(extension)) {
            return bufferPoolDirectory.openInput(name, context);
        }

        return super.openInput(name, context);
    }

    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        String extension = FileSwitchDirectory.getExtension(name);

        ensureOpen();
        ensureCanRead(name);

        if (delegeteBufferPool(extension)) {
            return bufferPoolDirectory.createOutput(name, context);
        }

        return super.createOutput(name, context);
    }

    /**
     * Routes all temporary file creation to NIO, bypassing the buffer pool.
     *
     * <p>Temporary files are short-lived intermediate outputs (e.g., during segment merges)
     * that are written once and immediately renamed. They don't benefit from buffer pool
     * caching or read-ahead, so we route them to the simpler NIO path to avoid wasting
     * limited buffer pool resources.
     *
     * @param prefix the prefix string to be used in generating the file's name
     * @param suffix the suffix string to be used in generating the file's name
     * @param context the IO context for this operation
     * @return an IndexOutput for writing to the temporary file
     * @throws IOException if an I/O error occurs
     */
    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        return super.createTempOutput(prefix, suffix, context);
    }

    @Override
    public void deleteFile(String name) throws IOException {
        // Route all deletes through NIOFS (super); do not delegate to the buffer-pool directory.
        super.deleteFile(name);
    }

    /**
     * Routes rename so the buffer-pool directory's cache invalidation actually runs under HYBRIDFS
     * (the default store type).
     *
     * <p>Without this override, {@code rename} would fall through to {@link org.apache.lucene.store.FSDirectory#rename}
     * (a bare {@code Files.move} with no cache invalidation), bypassing {@link BufferPoolDirectory#rename}. A rename that
     * replaces a buffer-pool-cached path would then leave stale FD-cache / block-cache / encryption-metadata entries for
     * the source and destination paths. Because the data read path is unauthenticated AES-CTR, a later read of the
     * reused path could be served the OLD inode's ciphertext while the footer/file-key is re-resolved from the NEW inode
     * — silent corruption (surfacing later as a Lucene CRC / CorruptIndexException). Mirrors {@link #deleteFile} routing.
     *
     * <p>We route to {@link BufferPoolDirectory#rename} when EITHER path is buffer-pool-routed (so the invalidation for
     * both the source's and destination's cached state runs); otherwise to {@code super.rename} for NIO-only files. Both
     * directories share the same underlying {@link org.apache.lucene.store.FSDirectory}, so the physical move is
     * identical regardless of which path performs it.
     */
    @Override
    public void rename(String source, String dest) throws IOException {
        String sourceExtension = FileSwitchDirectory.getExtension(source);
        String destExtension = FileSwitchDirectory.getExtension(dest);

        if (delegeteBufferPool(sourceExtension) || delegeteBufferPool(destExtension)) {
            bufferPoolDirectory.rename(source, dest);
        } else {
            super.rename(source, dest);
        }
    }

    @Override
    public void close() throws IOException {
        bufferPoolDirectory.close(); // only closes its resources.
        super.close(); // actually closes pending files.
    }
}
