/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.read_ahead.impl;

import java.nio.file.Path;

import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.read_ahead.Worker;

/**
 * No-op {@link Worker} implementation — read-ahead is disabled.
 *
 * <p>{@code schedule()} always returns {@code true} without doing any work; {@code close()}
 * and {@code cancel()} are no-ops. Used when we want to bypass the async prefetch layer
 * entirely (avoids the "Attempted schedule on closed worker" DEBUG cascade and the
 * QueuingWorker / IndexInput lifecycle race exposure between shard-close and prefetch).
 *
 * <p>Returning {@code true} from {@code schedule} is safe: {@link ReadaheadManagerImpl}
 * only checks the return value for internal bookkeeping; nothing in the read-path depends
 * on the prefetch actually completing.
 *
 * @opensearch.internal
 */
public final class NoopWorker implements Worker {

    @Override
    public <T extends AutoCloseable> boolean schedule(BlockCache<T> blockCache, Path path, long offset, long blockCount) {
        return true;
    }

    @Override
    public boolean isRunning() {
        return false;
    }

    @Override
    public int getQueueSize() {
        return 0;
    }

    @Override
    public int getQueueCapacity() {
        return 0;
    }

    @Override
    public void cancel(Path path) {
        // no-op
    }

    @Override
    public boolean isReadAheadPaused() {
        return true;
    }

    @Override
    public void close() {
        // no-op
    }
}
