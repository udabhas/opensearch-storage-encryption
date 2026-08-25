/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.apache.lucene.store.NIOFSDirectory;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;

/**
 * A NioFS directory implementation that encrypts all index files using a
 * user supplied key.
 *
 * <p>Most index files are encrypted when the crypto plugin is enabled. As a temporary
 * measure, {@code segments_N} and {@code .si} files are NOT encrypted and are delegated
 * to the plaintext NIOFS implementation for read, write, and length operations; encryption
 * for these will be added back later (it requires accompanying core changes). The read path
 * attempts decryption with a fallback to plaintext for backward compatibility with indices
 * created before encryption was enabled.
 *
 * @opensearch.internal
 */
public class CryptoNIOFSDirectory extends NIOFSDirectory {
    private static final Logger LOGGER = LogManager.getLogger(CryptoNIOFSDirectory.class);
    private final Provider provider;

    /** The resolver for encryption keys and initialization vectors. */
    public final KeyResolver keyResolver;

    private final AtomicLong nextTempFileCounter = new AtomicLong();
    private final int algorithmId = 1; // Default to AES_256_GCM_CTR
    private final Path dirPath;
    private final EncryptionMetadataCache encryptionMetadataCache;

    /**
     * Creates a new CryptoNIOFSDirectory with encryption support.
     *
     * @param lockFactory the lock factory for coordinating access
     * @param location the directory path
     * @param provider the security provider for cryptographic operations
     * @param keyResolver resolver for encryption keys and initialization vectors
     * @param encryptionMetadataCache cache for encryption metadata
     * @throws IOException if the directory cannot be created or accessed
     */
    public CryptoNIOFSDirectory(
        LockFactory lockFactory,
        Path location,
        Provider provider,
        KeyResolver keyResolver,
        EncryptionMetadataCache encryptionMetadataCache
    )
        throws IOException {
        super(location, lockFactory);
        this.provider = provider;
        this.keyResolver = keyResolver;
        this.dirPath = getDirectory();
        this.encryptionMetadataCache = encryptionMetadataCache;
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        try {
            final boolean trace = FdcDebug.on(LOGGER);
            final int callsite = trace ? FdcDebug.site(LOGGER, "niofs.openInput", name) : 0;
            // segments_N and .si files are intentionally NOT encrypted for now; delegate to the
            // plaintext NIOFS impl. Encryption for these will be added back later (requires core changes).
            if (name.contains("segments_") || name.endsWith(".si")) {
                traceNio(trace, "openInput", "PLAINTEXT-NIOFS-meta", name, context, callsite);
                return super.openInput(name, context);
            }

            ensureOpen();
            ensureCanRead(name);
            Path path = getDirectory().resolve(name);
            FileChannel fc = FileChannel.open(path, StandardOpenOption.READ);
            boolean success = false;

            try {
                final IndexInput indexInput = new CryptoBufferedIndexInput(
                    "CryptoBufferedIndexInput(path=\"" + path + "\")",
                    fc,
                    context,
                    this.keyResolver,
                    path,
                    this.encryptionMetadataCache
                );
                success = true;
                traceNio(trace, "openInput", "CRYPTO-BUFFERED", name, context, callsite);
                return indexInput;
            } catch (EncryptionFooter.NotOSEFFileException e) {
                // Plaintext file (no OSEF footer) — fall back to unencrypted read.
                IOUtils.closeWhileHandlingException(fc);
                success = true;
                traceNio(trace, "openInput", "PLAINTEXT-NIOFS-noFooter", name, context, callsite);
                return super.openInput(name, context);
            } finally {
                if (!success) {
                    IOUtils.closeWhileHandlingException(fc);
                }
            }
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.INDEX_INPUT_ERROR);
            throw e;
        }
    }

    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        try {
            final boolean trace = FdcDebug.on(LOGGER);
            final int callsite = trace ? FdcDebug.site(LOGGER, "niofs.createOutput", name) : 0;
            // segments_N and .si files are intentionally NOT encrypted for now; delegate to the
            // plaintext NIOFS impl. Encryption for these will be added back later (requires core changes).
            if (name.contains("segments_") || name.endsWith(".si")) {
                traceNio(trace, "createOutput", "PLAINTEXT-NIOFS-meta", name, context, callsite);
                return super.createOutput(name, context);
            }
            traceNio(trace, "createOutput", "CRYPTO-STREAM", name, context, callsite);

            ensureOpen();
            Path path = directory.resolve(name);

            OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

            try {
                return new CryptoOutputStreamIndexOutput(
                    name,
                    path,
                    fos,
                    this.keyResolver,
                    provider,
                    algorithmId,
                    path,
                    this.encryptionMetadataCache
                );
            } catch (Throwable t) {
                // Encrypting-output construction failed (e.g. key load threw): close the raw stream we just
                // opened so it does not leak. Otherwise the OutputStream is orphaned -> LeakFS failure in tests
                // and a real FD leak in prod when getDataKey()/KMS errors mid-createOutput.
                IOUtils.closeWhileHandlingException(fos);
                throw t;
            }
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.INDEX_OUTPUT_ERROR);
            throw e;
        }
    }

    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.createTempOutput", "prefix=" + prefix + " suffix=" + suffix, context);
        // segments_N and .si files are intentionally NOT encrypted for now; delegate to the
        // plaintext NIOFS impl. Encryption for these will be added back later (requires core changes).
        if (prefix.contains("segments_") || prefix.endsWith(".si")) {
            return super.createTempOutput(prefix, suffix, context);
        }

        ensureOpen();
        String name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        try {
            return new CryptoOutputStreamIndexOutput(
                name,
                path,
                fos,
                this.keyResolver,
                provider,
                algorithmId,
                path,
                this.encryptionMetadataCache
            );
        } catch (Throwable t) {
            // See createOutput: close the raw stream if the encrypting wrapper fails to construct, so it does
            // not leak (LeakFS failure in tests; real FD leak in prod on key/KMS errors).
            IOUtils.closeWhileHandlingException(fos);
            throw t;
        }
    }

    @Override
    public long fileLength(String name) throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.fileLength", "file=" + name);
        // segments_N and .si files are intentionally NOT encrypted for now; their on-disk length is
        // the true content length (no OSEF footer). Encryption for these will be added back later.
        if (name.contains("segments_") || name.endsWith(".si")) {
            return super.fileLength(name);
        }

        Path path = dirPath.resolve(name);
        long fileSize = super.fileLength(name);

        if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            return fileSize;
        }

        String normalizedPath = EncryptionMetadataCache.normalizePath(path);

        // check cache first
        EncryptionFooter cachedFooter = encryptionMetadataCache.getFooter(normalizedPath);
        if (cachedFooter != null) {
            return fileSize - cachedFooter.getFooterLength();
        }

        // read footer from disk with OSEF validation
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            try {
                EncryptionFooter footer = EncryptionFooter
                    .readViaFileChannel(normalizedPath, channel, keyResolver.getDataKey().getEncoded(), encryptionMetadataCache);
                return fileSize - footer.getFooterLength();
            } catch (EncryptionFooter.NotOSEFFileException e) {
                return fileSize;
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.close", "dir=" + getDirectory());
        isOpen = false;
        deletePendingFiles();
        encryptionMetadataCache.invalidateDirectory();
    }

    @Override
    public void rename(String source, String dest) throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.rename", "src=" + source + " dest=" + dest);
        super.rename(source, dest);
        // Invalidate BOTH source and destination paths in the encryption cache.
        // Source (pending_segments_N): clears stale frameIV cached during the write —
        // without this, the NEXT write to the same path reuses the old IV
        // (derived from a previous messageId) producing ciphertext that can't be
        // decrypted with the new messageId's IV.
        // Destination (segments_N): clears stale footer/frameIV from prior reads so a
        // recreated path is never served the previous inode's messageId/derived key
        // (which under the unauthenticated AES-CTR read decrypts to silent garbage).
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(dirPath.resolve(source)));
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(dirPath.resolve(dest)));
    }

    @Override
    public void deleteFile(String name) throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.deleteFile", "file=" + name);
        super.deleteFile(name);
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(dirPath.resolve(name)));
    }

    /**
     * fdc-debug (throwaway instrumentation). Records the OUTCOME of NIO-path routing, so a
     * plaintext fallback (no OSEF footer) is distinguishable from an encrypted read in the same log.
     */
    private static void traceNio(boolean trace, String op, String route, String name, IOContext context, int callsite) {
        if (trace == false) {
            return;
        }
        FdcDebug
            .log(
                LOGGER,
                "fdc-debug niofs.{} route={} file={} {} thread={} callsite={}",
                op,
                route,
                name,
                FdcDebug.describe(context),
                FdcDebug.thread(),
                callsite
            );
    }

    // ---- fdc-debug: trace-only overrides (no behaviour change; each logs and delegates) ----
    // openChecksumInput / obtainLock are final in Lucene 10.5 and cannot be traced here.

    @Override
    public String[] listAll() throws IOException {
        String[] all = super.listAll();
        FdcDebug.dirResult(LOGGER, "niofs.listAll", "dir=" + getDirectory(), all.length + " files");
        return all;
    }

    @Override
    public void sync(java.util.Collection<String> names) throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.sync", "files=" + names.size() + " " + names);
        super.sync(names);
    }

    @Override
    public void syncMetaData() throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.syncMetaData", "dir=" + getDirectory());
        super.syncMetaData();
    }

    @Override
    public void copyFrom(org.apache.lucene.store.Directory from, String src, String dest, IOContext context) throws IOException {
        FdcDebug.dirOp(LOGGER, "niofs.copyFrom", "from=" + from.getClass().getSimpleName() + " src=" + src + " dest=" + dest, context);
        super.copyFrom(from, src, dest, context);
    }

    @Override
    public java.util.Set<String> getPendingDeletions() throws IOException {
        java.util.Set<String> pending = super.getPendingDeletions();
        FdcDebug.dirResult(LOGGER, "niofs.getPendingDeletions", "dir=" + getDirectory(), pending);
        return pending;
    }
}
