/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FileOpenTracker {
    private static final Logger LOGGER = LogManager.getLogger(FileOpenTracker.class);
    private static final Map<String, AtomicLong> OPENS = new ConcurrentHashMap<>();

    public static void trackOpen(String path) {
        OPENS.computeIfAbsent(path, k -> new AtomicLong()).incrementAndGet();
    }

    public static void logStats() {
        LOGGER.info("=== File Open Stats ===");
        LOGGER.info("Total unique files: {}", OPENS.size());
        LOGGER.info("Total opens: {}", OPENS.values().stream().mapToLong(AtomicLong::get).sum());
        OPENS
            .entrySet()
            .stream()
            .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
            .forEach(e -> LOGGER.info("{} -> {}", e.getKey(), e.getValue().get()));
    }

    public static void reset() {
        OPENS.clear();
    }
}
