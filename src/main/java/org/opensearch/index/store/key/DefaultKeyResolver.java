/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.io.IOException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.index.store.cipher.OpenSslNativeCipher;

/**
 * Default implementation of {@link KeyResolver} responsible for managing
 * the encryption key used in encrypting and decrypting Lucene index files.
 *
 * Metadata files:
 * - "keyfile" stores the encrypted data key
 * - IVs are derived using HKDF
 *
 * @opensearch.internal
 */
public class DefaultKeyResolver implements KeyResolver {
    private static final Logger LOGGER = LogManager.getLogger(DefaultKeyResolver.class);

    private final Directory directory;
    private final MasterKeyProvider keyProvider;

    private Key dataKey;

    private static final String KEY_FILE = "keyfile";
    private static final String IV_FILE = "ivfile";
    private final byte[] baseIV;

    /**
     * Constructs a new {@link DefaultKeyResolver} and ensures the key is initialized.
     *
     * @param directory the Lucene directory to read/write metadata files
     * @param provider the JCE provider used for cipher operations
     * @param keyProvider the master key provider used to encrypt/decrypt data keys
     * @throws IOException if an I/O error occurs while reading or writing key metadata
     */
    public DefaultKeyResolver(Directory directory, Provider provider, MasterKeyProvider keyProvider) throws IOException {
        this.directory = directory;
        this.keyProvider = keyProvider;
        this.baseIV = new byte[16];
        initialize();
    }

    /**
     * Attempts to load the encrypted key from the directory.
     * If not present, it generates and persists new values.
     */
    private void initialize() throws IOException {
        try {
            dataKey = new SecretKeySpec(keyProvider.decryptKey(readByteArrayFile(KEY_FILE)), "AES");
        } catch (java.nio.file.NoSuchFileException e) {
            initNewKey();
        }
    }

    /**
     * Generates a new AES data key and writes it to metadata file.
     */
    private void initNewKey() throws IOException {
        DataKeyPair pair = keyProvider.generateDataPair();
        dataKey = new SecretKeySpec(pair.getRawKey(), "AES");
        writeByteArrayFile(KEY_FILE, pair.getEncryptedKey());
    }

    /**
     * Reads a byte array from the specified file in the directory.
     */
    private byte[] readByteArrayFile(String fileName) throws IOException {
        try (IndexInput in = directory.openInput(fileName, IOContext.READONCE)) {
            int size = in.readInt();
            byte[] bytes = new byte[size];
            in.readBytes(bytes, 0, size);
            return bytes;
        }
    }

    /**
     * Writes a byte array to the specified file in the directory.
     */
    private void writeByteArrayFile(String fileName, byte[] data) throws IOException {
        try (IndexOutput out = directory.createOutput(fileName, IOContext.DEFAULT)) {
            out.writeInt(data.length);
            out.writeBytes(data, 0, data.length);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Key getDataKey() {
        return dataKey;
    }

    // TODO: Remove this IV bytes and update translog to generate the IV bytes deterministically
    @Override
    public byte[] getIvBytes() {
        try {
            return readByteArrayFile(IV_FILE);
        } catch (java.nio.file.NoSuchFileException e) {
            initNewIV();
            return this.baseIV.clone();
        } catch (IOException ex) {
            LOGGER.info("Encountered exception during getIV -> ", ex);
            return this.baseIV.clone();
        }
    }

    private void initNewIV() {
        try {
            new SecureRandom().nextBytes(this.baseIV);
            writeByteArrayFile(IV_FILE, this.baseIV);
        } catch (IOException ex) {
            LOGGER.info("Encountered exception during initNewIV -> ", ex);
        }
    }
}