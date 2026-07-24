/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.CryptoDirectoryFactory;

import com.github.benmanes.caffeine.cache.Cache;

/**
 * I/O backend that uses Java NIO {@link FileChannel} with Direct I/O.
 *
 * <p>Reuses a node-level {@link FileChannel} cache (see
 * {@link CryptoDirectoryFactory#getOrCreateFileChannelCache()}) so repeated block-cache misses on
 * the same file do not re-pay an {@code open()}/{@code close()} syscall per load. Sharing one channel
 * across threads is safe because {@link DirectIOReaderUtil#directIOReadAligned} reads with the
 * <em>positional</em> {@code FileChannel.read(buffer, position)} form, which never mutates the
 * channel's shared position.
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
@SuppressForbidden(reason = "uses custom DirectIO and a shared FileChannel cache")
public class FileChannelBackend implements IOBackendStrategy {

    @Override
    public MemorySegment read(Path filePath, long offset, long length, Arena arena, int blockSize) throws IOException {
        FileChannel channel = getCachedChannel(filePath);
        try {
            return DirectIOReaderUtil.directIOReadAligned(channel, offset, length, arena, blockSize);
        } catch (ClosedByInterruptException e) {
            // THIS thread was interrupted while blocked in the read (e.g. query/task cancellation). The
            // InterruptibleChannel contract closed the (shared, node-cached) FD as a side effect and left
            // this thread's interrupt flag set. A fresh-channel retry would immediately re-throw
            // ClosedByInterruptException (interrupt still set) and close that FD too, so DON'T retry.
            // Invalidate the now-closed cached channel so other readers re-open instead of drawing the
            // dead FD, re-assert the interrupt, and surface a cancellation-shaped InterruptedIOException
            // rather than a corruption-shaped IOException.
            CryptoDirectoryFactory.getOrCreateFileChannelCache().invalidate(cacheKey(filePath));
            Thread.currentThread().interrupt();
            InterruptedIOException iioe = new InterruptedIOException(
                "Interrupted during Direct-I/O read of " + filePath + " at offset " + offset
            );
            iioe.initCause(e);
            throw iioe;
        } catch (ClosedChannelException e) {
            // The cached channel was closed by something OTHER than this thread's interrupt: size-based
            // eviction, a concurrent deleteFile, or another reader's interrupt closing the shared FD
            // (AsynchronousCloseException). Drop the stale entry and serve this read from a fresh one-shot
            // channel — this is the victim-recovery path.
            CryptoDirectoryFactory.getOrCreateFileChannelCache().invalidate(cacheKey(filePath));
            // Guard the retry: if THIS thread is itself interrupted, opening/reading a fresh channel would
            // just throw ClosedByInterruptException again. Convert to a clean cancellation instead.
            if (Thread.currentThread().isInterrupted()) {
                InterruptedIOException iioe = new InterruptedIOException(
                    "Interrupted before Direct-I/O retry of " + filePath + " at offset " + offset
                );
                iioe.initCause(e);
                throw iioe;
            }
            try (FileChannel fresh = openDirect(filePath)) {
                return DirectIOReaderUtil.directIOReadAligned(fresh, offset, length, arena, blockSize);
            }
        }
    }

    private static FileChannel getCachedChannel(Path filePath) throws IOException {
        Cache<String, FileChannel> cache = CryptoDirectoryFactory.getOrCreateFileChannelCache();
        try {
            return cache.get(cacheKey(filePath), k -> {
                try {
                    return openDirect(filePath);
                } catch (IOException ioe) {
                    // Caffeine's mapping function cannot throw checked exceptions; wrap and unwrap below.
                    throw new UncheckedOpenException(ioe);
                }
            });
        } catch (UncheckedOpenException u) {
            throw u.getCause();
        }
    }

    @SuppressForbidden(reason = "uses custom DirectIO")
    private static FileChannel openDirect(Path filePath) throws IOException {
        return FileChannel.open(filePath, StandardOpenOption.READ, DirectIOReaderUtil.getDirectOpenOption());
    }

    private static String cacheKey(Path filePath) {
        // Single source of truth for the key format, shared with the delete/rename invalidation path
        // in CryptoDirectoryFactory so producer and consumer keys can never drift.
        return CryptoDirectoryFactory.fileChannelCacheKey(filePath);
    }

    /** Wraps a checked {@code open()} failure so it can pass through Caffeine's mapping function. */
    private static final class UncheckedOpenException extends RuntimeException {
        UncheckedOpenException(IOException cause) {
            super(cause);
        }

        @Override
        public synchronized IOException getCause() {
            return (IOException) super.getCause();
        }
    }
}
