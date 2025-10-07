/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Set;

import org.opensearch.index.store.key.KeyResolver;
/**
 * A ChannelFactory implementation that creates FileChannels with transparent
 * AES-GCM encryption/decryption for translog files.
 *
 * This factory determines whether to apply encryption based on the file extension:
 * - .tlog files: Encrypted using AES-GCM with 8KB authenticated chunks
 * - .ckp files: Not encrypted (checkpoint metadata)
 *
 * Updated to use unified KeyResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * @opensearch.internal
 */
public class CryptoChannelFactory implements ChannelFactory {

    private final KeyResolver keyResolver;
    private final String translogUUID;

    /**
     * Creates a new CryptoChannelFactory.
     *
     * @param keyResolver the key and IV resolver for encryption keys (unified with index files)
     * @param translogUUID the translog UUID for exact header size calculation
     */
    public CryptoChannelFactory(KeyResolver keyResolver, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.keyResolver = keyResolver;
        this.translogUUID = translogUUID;
    }

    @Override
    public FileChannel open(Path path, OpenOption... options) throws IOException {
        FileChannel baseChannel = FileChannel.open(path, options);

        if (!path.getFileName().toString().endsWith(".tlog")) {
            return baseChannel;
        }

        Set<OpenOption> optionsSet = Set.of(options);
        return new CryptoFileChannelWrapper(baseChannel, keyResolver, path, optionsSet, translogUUID);
    }
}
