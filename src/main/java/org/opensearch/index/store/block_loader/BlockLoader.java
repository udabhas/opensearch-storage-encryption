/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import java.io.IOException;
import java.nio.file.Path;

import org.opensearch.index.store.block_cache.BlockCacheKey;

/**
 * Interface for loading blocks of data from files into memory.
 * 
 * <p>BlockLoader implementations are responsible for efficiently reading file data
 * and providing it in a format suitable for caching. This typically involves
 * managing memory allocation from pools and handling various I/O operations.
 *
 * @param <T> the type of loaded block data (e.g., RefCountedByteBuffer)
 * @opensearch.internal
 */
public interface BlockLoader<T> {

    /**
     * Thrown when the memory segment pool is under pressure and cannot allocate segments.
     */
    class PoolPressureException extends IOException {
        /**
         * Constructs a new PoolPressureException with the specified detail message.
         *
         * @param message the detail message explaining the pool pressure condition
         */
        public PoolPressureException(String message) {
            super(message);
        }

        /**
         * Constructs a new PoolPressureException with the specified detail message and cause.
         *
         * @param message the detail message explaining the pool pressure condition
         * @param cause the underlying cause of the exception
         */
        public PoolPressureException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Thrown when unable to acquire a memory segment from the pool within timeout.
     */
    class PoolAcquireFailedException extends IOException {
        /**
         * Constructs a new PoolAcquireFailedException with the specified detail message.
         *
         * @param message the detail message explaining the acquisition failure
         */
        public PoolAcquireFailedException(String message) {
            super(message);
        }

        /**
         * Constructs a new PoolAcquireFailedException with the specified detail message and cause.
         *
         * @param message the detail message explaining the acquisition failure
         * @param cause the underlying cause of the exception
         */
        public PoolAcquireFailedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Thrown when block loading fails due to I/O or other loading errors.
     */
    class BlockLoadFailedException extends IOException {
        /**
         * Constructs a new BlockLoadFailedException with the specified detail message.
         *
         * @param message the detail message explaining the loading failure
         */
        public BlockLoadFailedException(String message) {
            super(message);
        }

        /**
         * Constructs a new BlockLoadFailedException with the specified detail message and cause.
         *
         * @param message the detail message explaining the loading failure
         * @param cause the underlying cause of the exception
         */
        public BlockLoadFailedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Load one or more blocks efficiently with specified pool acquisition timeout.
     *
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to read
     * @param poolTimeoutMs timeout in milliseconds for acquiring pool segments
     *                      (use 50ms for prefetch, 5000ms for on-demand loads)
     * @return array of loaded memory segments (length equals blockCount)
     * @throws Exception if loading fails due to I/O errors, pool pressure, or other issues
     */
    T[] load(Path filePath, long startOffset, long blockCount, long poolTimeoutMs) throws Exception;

    /**
     * Load one or more blocks efficiently with default timeout (5 seconds for critical loads).
     *
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to read
     * @return array of loaded memory segments (length equals blockCount)
     * @throws Exception if loading fails due to I/O errors, pool pressure, or other issues
     */
    default T[] load(Path filePath, long startOffset, long blockCount) throws Exception {
        return load(filePath, startOffset, blockCount, 5000); // 5 seconds for critical on-demand loads
    }

    /**
     * Load blocks, optionally backing each with a NON-POOLED buffer ({@code heapOnly}): no pool
     * acquire, so no buffersInUse accounting, no allocation limit, no throttle, no stall loop. For
     * readers that read a block once and discard it. This is an intentional bypass, NOT the degraded
     * read that uses the same buffer shape when the pool is exhausted — keep the two counted apart.
     *
     * <p>Default ignores {@code heapOnly}, so implementations without a non-pooled mode are unchanged.
     *
     * @param filePath file to read from
     * @param startOffset starting file offset (should be block-aligned)
     * @param blockCount number of blocks to read
     * @param poolTimeoutMs pool acquire timeout (unused when {@code heapOnly} is honoured)
     * @param heapOnly when true, back every block with a non-pooled buffer
     * @return array of loaded blocks (length equals blockCount)
     * @throws Exception if loading fails
     */
    default T[] load(Path filePath, long startOffset, long blockCount, long poolTimeoutMs, boolean heapOnly) throws Exception {
        return load(filePath, startOffset, blockCount, poolTimeoutMs);
    }

    /**
     * Loads a single block using the provided cache key.
     *
     * @param key the cache key identifying the block to load
     * @return the loaded block data
     * @throws Exception if loading fails due to I/O errors, pool pressure, or other issues
     */
    default T load(BlockCacheKey key) throws Exception {
        T[] result = load(key.filePath(), key.offset(), 1);  // Load 1 block
        if (result.length == 0 || result[0] == null) {
            throw new IOException("Failed to load block for key: " + key);
        }
        return result[0];
    }

    /**
     * Loads a single block into a NON-POOLED buffer. See {@link #load(Path, long, long, long, boolean)}.
     *
     * <p>Keeps {@link #load(BlockCacheKey)}'s 5s timeout so an implementation that ignores
     * {@code heapOnly} behaves exactly as today rather than failing fast.
     *
     * @param key the cache key identifying the block to load
     * @return the loaded block, backed by a non-pooled buffer
     * @throws Exception if loading fails
     */
    default T loadTransient(BlockCacheKey key) throws Exception {
        T[] result = load(key.filePath(), key.offset(), 1, 5000, true);
        if (result.length == 0 || result[0] == null) {
            throw new IOException("Failed to load block for key: " + key);
        }
        return result[0];
    }
}
