/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cache;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.metrics.FileOpenTracker;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;

/**
 * A cache for FileChannel instances backed by Caffeine.
 *
 * <p>Caches open FileChannels keyed by (path, openOptions) to avoid repeated
 * open/close syscalls. Channels are closed automatically on eviction or
 * explicit invalidation via the removal listener.
 *
 * <p>The key includes open options because a FileChannel opened with READ
 * cannot be used for Direct I/O — the DIRECT flag must be set at open time.
 */
public class FileChannelCache {
    private static final Logger LOGGER = LogManager.getLogger(FileChannelCache.class);
    private static final int MAX_ENTRIES = 100_000;

    private static final Cache<String, FileChannel> CACHE = Caffeine.newBuilder()
        .maximumSize(MAX_ENTRIES)
        .recordStats()
        .removalListener((String key, FileChannel channel, RemovalCause cause) -> {
            if (channel != null) {
                try {
                    channel.close();
                } catch (IOException e) {
                    LOGGER.warn("Failed to close FileChannel on {}: key={}", cause, key, e);
                }
            }
        })
        .build();

    private static String buildKey(Path path, OpenOption... options) {
        String pathKey = path.toAbsolutePath().normalize().toString();
        if (options == null || options.length == 0) {
            return pathKey;
        }
        String optionsKey = Arrays.stream(options).map(Object::toString).sorted().reduce((a, b) -> a + "," + b).orElse("");
        return pathKey + "|" + optionsKey;
    }

    /**
     * Returns a cached FileChannel for the given path and options, opening one if absent.
     * This is atomic — no TOCTOU race.
     *
     * @throws IOException if the file cannot be opened
     */
    public static FileChannel getOrOpen(Path path, OpenOption... options) throws IOException {
        String key = buildKey(path, options);
        try {
            return CACHE.get(key, k -> {
                try {
                    FileOpenTracker.trackOpen(path.toAbsolutePath().normalize().toString());
                    return FileChannel.open(path, options);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    /**
     * Invalidates all cached channels whose key starts with the given path.
     * This handles both READ and READ+DIRECT variants for the same file.
     * Triggers the removal listener which closes the channels.
     */
    public static void invalidate(Path path) {
        String pathPrefix = path.toAbsolutePath().normalize().toString();
        List<String> keysToRemove = CACHE.asMap()
            .keySet()
            .stream()
            .filter(k -> k.startsWith(pathPrefix))
            .toList();
        if (!keysToRemove.isEmpty()) {
            CACHE.invalidateAll(keysToRemove);
        }
    }

    /**
     * Closes all cached channels.
     */
    public static void closeAll() {
        CACHE.invalidateAll();
    }

    public static long size() {
        return CACHE.estimatedSize();
    }

    /**
     * Returns cache statistics for debugging/monitoring.
     */
    public static String stats() {
        var s = CACHE.stats();
        return String.format(
            "FileChannelCache[size=%d, hits=%d, misses=%d, hitRate=%.2f%%, evictions=%d, avgLoadMs=%.2f]",
            CACHE.estimatedSize(),
            s.hitCount(),
            s.missCount(),
            s.hitRate() * 100,
            s.evictionCount(),
            s.averageLoadPenalty() / 1_000_000.0
        );
    }
}