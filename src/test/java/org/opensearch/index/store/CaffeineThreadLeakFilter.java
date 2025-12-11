/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import com.carrotsearch.randomizedtesting.ThreadFilter;

/**
 * Caffeine cache uses ForkJoinPool.commonPool() for async maintenance tasks (eviction, stats updates).
 * These are JVM-managed daemon threads that remain in TIMED_WAITING state waiting for more work.
 * They are not a real leak - they're shared JVM-wide and automatically cleaned up on JVM exit.
 * This filter excludes those threads from the leak detection logic.
 *
 * @see <a href="https://github.com/ben-manes/caffeine/issues/396">Caffeine ForkJoinPool usage</a>
 */
public final class CaffeineThreadLeakFilter implements ThreadFilter {
    @Override
    public boolean reject(Thread t) {
        return t.getName().startsWith("ForkJoinPool.commonPool-");
    }
}
