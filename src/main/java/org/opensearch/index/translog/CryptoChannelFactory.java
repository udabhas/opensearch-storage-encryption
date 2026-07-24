/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.opensearch.common.util.io.IOUtils;
import org.opensearch.index.store.key.KeyResolver;

/**
 * A ChannelFactory implementation that creates FileChannels with transparent
 * AES-GCM encryption/decryption for translog files.
 *
 * This factory determines whether to apply encryption based on the file extension:
 * - .tlog files: Encrypted using AES-GCM with 8KB authenticated chunks
 * - .ckp files: Not encrypted (checkpoint metadata)
 *
 * Updated to use unified KeyResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * The factory also tracks the current writer's wrapper to enable cipher finalization
 * before remote upload (decrypt-before-upload flow).
 *
 * @opensearch.internal
 */
public class CryptoChannelFactory implements ChannelFactory {

    private final KeyResolver keyResolver;
    private final String translogUUID;
    private final Map<Path, CryptoFileChannelWrapper> wrappers = new ConcurrentHashMap<>();

    /**
     * Creates a new CryptoChannelFactory.
     *
     * @param keyResolver the key and IV resolver for encryption keys (unified with index files)
     * @param translogUUID the translog UUID for exact header size calculation
     */
    public CryptoChannelFactory(KeyResolver keyResolver, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        // Fail fast on a null resolver. Base-IV derivation is lazy (deferred to the first super-header
        // write/read), so without this check a null resolver would only NPE later at the first frame op.
        if (keyResolver == null) {
            throw new IllegalArgumentException("keyResolver is required for translog encryption");
        }
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
    }

    @Override
    public FileChannel open(Path path, OpenOption... options) throws IOException {
        if (!path.getFileName().toString().endsWith(".tlog")) {
            return FileChannel.open(path, options);
        }

        // Restore-from-plaintext safety: core caches a recovery reader's FileChannel (final field) through
        // THIS open() before the post-constructor re-encrypt sweep runs. A decrypting wrapper over plaintext
        // would fail on read, and a later Files.move can't fix an already-open fd (rename keeps the old
        // inode). So convert plaintext -> encrypted in place first, binding the cached channel to the
        // encrypted inode. No-op for already-encrypted files. Skip CREATE/CREATE_NEW: a brand-new generation
        // has nothing to convert, and touching the not-yet-created path would break creation.
        if (!isCreatingNewFile(options) && Files.exists(path)) {
            ensureEncryptedOnDisk(path);
        }

        FileChannel baseChannel = FileChannel.open(path, options);
        Set<OpenOption> optionsSet = Set.of(options);
        // Drop the wrapper from `wrappers` on close so the map doesn't leak one stale entry per
        // generation. The callback removes only if this exact wrapper is still tracked, so an older reader
        // closing cannot evict a newer writer that reused the path.
        CryptoFileChannelWrapper[] self = new CryptoFileChannelWrapper[1];
        CryptoFileChannelWrapper wrapper = new CryptoFileChannelWrapper(
            baseChannel,
            keyResolver,
            path,
            optionsSet,
            translogUUID,
            () -> wrappers.remove(path, self[0])
        );
        self[0] = wrapper;

        // Track wrapper by path for later finalization
        wrappers.put(path, wrapper);
        return wrapper;
    }

    /**
     * Returns true if {@code options} indicate the caller is creating a brand-new file (CREATE or
     * CREATE_NEW). A fresh translog generation is opened this way and has no existing bytes to convert.
     */
    private static boolean isCreatingNewFile(OpenOption... options) {
        for (OpenOption o : options) {
            if (o == StandardOpenOption.CREATE || o == StandardOpenOption.CREATE_NEW) {
                return true;
            }
        }
        return false;
    }

    /**
     * Ensures the on-disk {@code .tlog} is in the encrypted format, converting genuinely-plaintext
     * downloaded data in place. Idempotent: a file already carrying the super-header (or a header-only file)
     * is left untouched. Runs synchronously before the channel is created (so a cached reader binds to the
     * encrypted inode) and is crash-safe (write to a temp sibling, then atomic rename).
     *
     * @param path the translog file path
     * @throws IOException if the file cannot be read, converted, or atomically replaced
     */
    private void ensureEncryptedOnDisk(Path path) throws IOException {
        int headerSize = TranslogFrameManager.calculateTranslogHeaderSizeStatic(translogUUID);

        long fileSize = Files.size(path);
        if (fileSize <= headerSize) {
            // Header-only / empty data region: nothing to encrypt yet, and not a v3-detectable file.
            return;
        }

        // Stream the conversion (no Files.readAllBytes): read the core header, pipe the data region through
        // the frame manager in bounded buffers — avoids OOM on a large generation.
        try (FileChannel in = FileChannel.open(path, StandardOpenOption.READ)) {
            // Probe the core header plus the super-header magic so hasSuperHeaderMagic can actually inspect the
            // magic bytes (it needs headerSize + MAGIC.length; a headerSize-only buffer always misses).
            int probeSize = headerSize + TranslogFrameManager.MAGIC.length;
            ByteBuffer headerBuf = ByteBuffer.allocate(probeSize);
            if (readFully(in, headerBuf, 0) < headerSize) {
                return; // truncated below the header
            }
            // Already encrypted (magic present): leave it alone (don't double-encrypt or mask a format error).
            if (TranslogFrameManager.hasSuperHeaderMagic(headerBuf.array(), headerSize)) {
                return;
            }

            // Plaintext: convert in place via crash-safe temp+rename, streaming [headerSize, fileSize).
            Path tempFile = path.resolveSibling(path.getFileName().toString() + ".enc.tmp");
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
                    headerBuf.position(0).limit(headerSize); // write back only the core header, not the magic probe
                    out.write(headerBuf, 0); // plaintext core-header passthrough
                    TranslogFrameManager tfm = new TranslogFrameManager(out, keyResolver, path, translogUUID);
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
                                throw new IOException("no progress converting translog file:" + path);
                            }
                            logicalPos += accepted;
                            srcPos += accepted;
                        }
                    }
                    tfm.close();
                    out.force(true);
                }
                Files.move(tempFile, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                // fsync the parent dir so the rename is crash-durable (mirrors core TruncateTranslogAction);
                // without it a crash can leave the name pointing back at the old plaintext inode.
                if (path.getParent() != null) {
                    IOUtils.fsync(path.getParent(), true);
                }
            } catch (IOException | RuntimeException ex) {
                Files.deleteIfExists(tempFile); // no orphan temp on failure (original untouched until rename)
                throw ex;
            }
        }
    }

    private static final int CONVERT_BUFFER_SIZE = 1 << 20; // 1 MiB streaming buffer (avoids readAllBytes)

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
     * Finalizes the cipher for a specific file path.
     * This writes authentication tags to disk so the file can be decrypted.
     * 
     * This is for the decrypt-before-upload flow:
     * 1. Called before upload for the specific file being uploaded
     * 2. Writes authentication tags to complete encryption
     * 3. Enables successful decryption during snapshot read
     * 
     * @param path the path of the file to finalize
     * @throws IOException if finalization fails
     */
    public void finalizeForPath(Path path) throws IOException {
        CryptoFileChannelWrapper wrapper = wrappers.get(path);
        if (wrapper != null) {
            wrapper.getChunkManager().close();
        }
    }

    /**
     * Test-visibility hook: the number of wrappers currently tracked. Used to assert that closing a
     * channel drops its tracking entry rather than leaking it for the shard's lifetime.
     *
     * @return the count of tracked wrappers
     */
    int trackedWrapperCount() {
        return wrappers.size();
    }
}
