/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cache;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.metrics.FileOpenTracker;

public class FileChannelCache {
    private static final Logger LOGGER = LogManager.getLogger(FileChannelCache.class);

    private static final Map<String, FileChannel> CACHE = new ConcurrentHashMap<>();

    public static FileChannel getOrOpen(Path path, OpenOption... options) {
        String key = path.toAbsolutePath().normalize().toString();
        FileChannel fc = null;
        FileChannel cached = CACHE.get(key);
        if (cached != null && cached.isOpen()) {
            return cached;
        }
        try {
            FileOpenTracker.trackOpen(key);
            FileChannel channel = FileChannel.open(path, options);
            FileChannel existing = CACHE.putIfAbsent(key, channel);
            if (existing != null && existing.isOpen()) {
                channel.close();
                fc = existing;
                return existing;
            }
            return channel;
        } catch (IOException exception) {
            LOGGER.error("failed to open FileChannel for path : {} ", path, exception);
        }
        LOGGER.info("return NULL FILECHANNEL for path: {}", path);
        return fc;
    }

    public static void invalidate(Path path) {
        String key = path.toAbsolutePath().normalize().toString();
        FileChannel ch = CACHE.remove(key);
        if (ch != null)
            try {
                ch.close();
            } catch (IOException ignored) {}
    }

    public static void closeAll() {
        CACHE.forEach((k, v) -> {
            try {
                v.close();
            } catch (IOException ignored) {}
        });
        CACHE.clear();
    }

    public static int size() {
        return CACHE.size();
    }

}
