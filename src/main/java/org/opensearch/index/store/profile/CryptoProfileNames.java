/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.profile;

/**
 * Metric key names for the storage-encryption query profiler. Single source of truth so the
 * registration site, the read-path recording site, and any dashboards share identical keys.
 *
 * <p>To add a new cost center: add a name here, register a supplier for it in
 * {@code CryptoDirectoryPlugin.getQueryProfileMetricsProvider()}, and record into it at the call
 * site via {@code CryptoQueryProfile.from(ProfileBreakdownHolder.get())}.
 */
public final class CryptoProfileNames {

    private CryptoProfileNames() {}

    /** Wall-clock time spent in AES-CTR frame-based decrypt (Timer). */
    public static final String DECRYPT = "crypto_decrypt";
}
