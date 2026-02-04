/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cache;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.time.Duration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.metrics.FileOpenTracker;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;

public class FileChannelCache {
    private static final Logger LOGGER = LogManager.getLogger(FileChannelCache.class);
    private static final int MAX_ENTRIES = 10_000;
    private static final Duration EXPIRE_AFTER_ACCESS = Duration.ofMinutes(30);

    private static final Cache<String, FileChannel> CACHE = Caffeine
        .newBuilder()
        .maximumSize(MAX_ENTRIES)
        .expireAfterAccess(EXPIRE_AFTER_ACCESS)
        .removalListener((String key, FileChannel channel, RemovalCause cause) -> {
            if (channel != null) {
                try {
                    channel.close();
                } catch (IOException ignored) {}
                LOGGER.debug("Closed FileChannel for {} due to {}", key, cause);
            }
        })
        .build();

    public static FileChannel getOrOpen(Path path, OpenOption... options) {
        String key = path.toAbsolutePath().normalize().toString();
        return CACHE.get(key, k -> {
            try {
                FileOpenTracker.trackOpen(k);
                return FileChannel.open(path, options);
            } catch (IOException e) {
                LOGGER.error("Failed to open FileChannel for path: {}", path, e);
                return null;
            }
        });
    }

    public static void invalidate(Path path) {
        String key = path.toAbsolutePath().normalize().toString();
        CACHE.invalidate(key);
    }

    public static void closeAll() {
        CACHE.invalidateAll();
    }

    public static long size() {
        return CACHE.estimatedSize();
    }
}
