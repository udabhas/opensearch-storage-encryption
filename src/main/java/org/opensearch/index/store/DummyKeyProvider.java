/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.util.Collections;
import java.util.Map;

import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;

/**
 * Utility class providing a dummy MasterKeyProvider implementation for testing.
 * This is used by yamlRestTests and integration tests to avoid requiring
 * a real KMS plugin during testing.
 * 
 * <p><b>WARNING:</b> This is for testing purposes only and should never be 
 * used in production environments. The dummy provider:
 * <ul>
 * <li>Generates random keys without actual encryption</li>
 * <li>Returns encrypted keys as-is during decryption (no actual decryption)</li>
 * <li>Provides no real security</li>
 * </ul>
 *
 * @opensearch.internal
 */
public final class DummyKeyProvider {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private DummyKeyProvider() {
        throw new AssertionError("Utility class should not be instantiated");
    }

    /**
     * Creates a dummy MasterKeyProvider for testing purposes.
     * This provider generates random keys and returns encrypted keys as-is.
     * 
     * @return a mock MasterKeyProvider suitable for testing
     */
    public static MasterKeyProvider create() {
        return new MasterKeyProvider() {
            @Override
            public DataKeyPair generateDataPair() {
                // Deterministic key (was random). internalClusterTest runs every node in ONE JVM sharing the
                // static key caches (ShardKeyResolverRegistry / NodeLevelKeyCache, keyed by shard, not node),
                // so a random key would differ per in-process node and break cross-node recovery with a
                // footer-auth mismatch. A fixed key makes every node resolve the SAME data key — matching prod,
                // where KMS decrypt of a shared encrypted-DEK is deterministic across nodes. decryptKey echoes
                // its input, so this fixed value is the effective AES key. Test-only provider; never prod.
                byte[] key = new byte[32];
                for (int i = 0; i < key.length; i++) {
                    key[i] = (byte) (i + 1);
                }
                return new DataKeyPair(key.clone(), key.clone());
            }

            @Override
            public byte[] decryptKey(byte[] encryptedKey) {
                // For mock/testing purposes, just return the input as-is
                return encryptedKey;
            }

            @Override
            public String getKeyId() {
                return "builtin-mock-key-id";
            }

            @Override
            public Map<String, String> getEncryptionContext() {
                return Collections.emptyMap();
            }

            @Override
            public void close() {
                // Nothing to close for mock implementation
            }
        };
    }
}
