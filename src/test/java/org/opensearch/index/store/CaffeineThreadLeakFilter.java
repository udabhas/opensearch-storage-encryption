/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import org.opensearch.common.SuppressForbidden;

import com.carrotsearch.randomizedtesting.ThreadFilter;

/**
 * Thread leak filter for Caffeine cache's ForkJoinPool worker threads
 * and the plugin's daemon telemetry loggers, which the randomized-test
 * framework may otherwise flag as leaks at test-class teardown.
 *
 * <p>The daemon telemetry threads have a JVM-static lifetime by design
 * (they start once via CAS-guarded init and are never joined), so a
 * per-test cleanup would just re-add the flakiness. Filtering them out
 * is the right call.
 */
@SuppressForbidden(reason = "Thread matching for test leak filtering")
public class CaffeineThreadLeakFilter implements ThreadFilter {
    @Override
    public boolean reject(Thread t) {
        String name = t.getName();
        return name.startsWith("ForkJoinPool.commonPool-worker-")
            || name.equals("DirectIOBufferPoolStatsLogger")
            || name.equals("pool-gc-debt-monitor");
    }
}
