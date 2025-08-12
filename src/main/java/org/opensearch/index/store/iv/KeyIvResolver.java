/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.security.Key;

/**
 * An abstraction for resolving the symmetric encryption key used for encrypting and 
 * decrypting index files in an OpenSearch Directory implementation.
 *
 * Implementations of this interface are responsible for securely retrieving or generating
 * the key used in symmetric encryption (e.g., AES-CTR). IVs are derived using HKDF.
 *
 * @opensearch.internal
 */
public interface KeyIvResolver {

    /**
     * Returns the symmetric encryption key used for cipher operations.
     *
     * @return the decrypted symmetric {@link Key}, typically AES
     */
    Key getDataKey();
}