/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cache;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.metrics.FileOpenTracker;

public class FileChannelCache {
    private static final Logger LOGGER = LogManager.getLogger(FileChannelCache.class);

    private static final Map<String, FileChannel> CACHE = new ConcurrentHashMap<>();

    private static String buildKey(Path path, OpenOption... options) {
        String pathKey = path.toAbsolutePath().normalize().toString();
        if (options == null || options.length == 0) {
            return pathKey;
        }
        String optionsKey = Arrays.stream(options)
                .map(Object::toString)
                .sorted()
                .reduce((a, b) -> a + "," + b)
                .orElse("");
        return pathKey + "|" + optionsKey;
    }

    public static FileChannel getOrOpen(Path path, OpenOption... options) {
        String key = buildKey(path, options);
        FileChannel cached = CACHE.get(key);
        if (cached != null && cached.isOpen()) {
            return cached;
        }
        try {
            FileOpenTracker.trackOpen(path.toAbsolutePath().normalize().toString());
            FileChannel channel = FileChannel.open(path, options);
            FileChannel existing = CACHE.putIfAbsent(key, channel);
            if (existing != null && existing.isOpen()) {
                channel.close();
                return existing;
            }
            return channel;
        } catch (IOException e) {
            LOGGER.error("Failed to open FileChannel for path: {}", path, e);
        }
        LOGGER.info("return NULL FILECHANNEL for path: {}", path);
        return null;
    }

    public static void invalidate(Path path) {
        String pathPrefix = path.toAbsolutePath().normalize().toString();
        CACHE.entrySet().removeIf(entry -> {
            if (entry.getKey().startsWith(pathPrefix)) {
                try { entry.getValue().close(); } catch (IOException ignored) {}
                return true;
            }
            return false;
        });
    }

    public static void closeAll() {
        CACHE.forEach((k, v) -> {
            try { v.close(); } catch (IOException ignored) {}
        });
        CACHE.clear();
    }

    public static int size() {
        return CACHE.size();
    }
}
