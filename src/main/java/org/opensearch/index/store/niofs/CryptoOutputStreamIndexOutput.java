/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;

import org.apache.lucene.store.OutputStreamIndexOutput;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.cipher.AesGcmCipherFactory;
import org.opensearch.index.store.cipher.EncryptionAlgorithm;
import org.opensearch.index.store.cipher.EncryptionCache;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.key.KeyResolver;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.Provider;
import java.util.Arrays;

/**
 * An IndexOutput implementation that encrypts data before writing using native
 * OpenSSL AES-CTR.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "temporary bypass")
public final class CryptoOutputStreamIndexOutput extends OutputStreamIndexOutput {

    private static final int CHUNK_SIZE = 8_192;
    private static final int BUFFER_SIZE = 65_536;

    /**
     * Creates a new CryptoIndexOutput with per-file key derivation
     *
     * @param name The name of the output
     * @param path The path to write to
     * @param os The output stream
     * @param keyResolver The key/IV resolver for directory keys
     * @param provider The JCE provider to use
     */
    public CryptoOutputStreamIndexOutput(String name, Path path, OutputStream os, KeyResolver keyResolver, java.security.Provider provider, int algorithmId, Path filePath) {
        super("FSIndexOutput(path=\"" + path + "\")", name, new EncryptedOutputStream(os, keyResolver, provider, algorithmId, filePath), CHUNK_SIZE);
    }

    private static class EncryptedOutputStream extends FilterOutputStream {

        private final Key fileKey;
        private final byte[] directoryKey;
        private final byte[] buffer;
        private final EncryptionFooter footer;
        private final Provider provider;
        private final long frameSizeMask;
        private final int frameSizePower;
        private final EncryptionAlgorithm algorithm;

        // Frame tracking
        // TODO: CurrentCipher to be MemorySegment type for supporting openssl native cipher. Comment out current Cipher
        private Cipher currentCipher;
        private int currentFrameNumber = 0;
        private long currentFrameOffset = 0;
        private int bufferPosition = 0;
        private long streamOffset = 0;
        private int totalFrames = 0;
        private boolean isClosed = false;

        private final Path filePath;
        private final String filePathString;

        EncryptedOutputStream(OutputStream os, KeyResolver keyResolver, java.security.Provider provider, int algorithmId, Path filePath) {
            super(os);

            this.frameSizePower = EncryptionMetadataTrailer.DEFAULT_FRAME_SIZE_POWER;
            this.frameSizeMask = (1L << frameSizePower) - 1;

            // Generate MessageId and derive file-specific key
            this.footer = EncryptionFooter.generateNew(1L << frameSizePower, (short)algorithmId);
            this.directoryKey = keyResolver.getDataKey().getEncoded();
            byte[] derivedKey = HkdfKeyDerivation.deriveFileKey(directoryKey, footer.getMessageId());
            this.fileKey = new javax.crypto.spec.SecretKeySpec(derivedKey, "AES");

            this.provider = provider;
            this.algorithm = EncryptionAlgorithm.fromId((short) algorithmId);
            this.buffer = new byte[BUFFER_SIZE];

            this.filePath = filePath;
            this.filePathString = filePath.toAbsolutePath().toString();

            // Initialize first frame cipher
            initializeFrameCipher(0, 0);
        }

        @Override
        public void write(byte[] b, int offset, int length) throws IOException {
            checkClosed();
            if (b == null) {
                throw new NullPointerException("Input buffer cannot be null");
            }
            if (offset < 0 || length < 0 || offset + length > b.length) {
                throw new IndexOutOfBoundsException("Invalid offset or length");
            }
            if (length == 0)
                return;

            if (length >= BUFFER_SIZE) {
                flushBuffer();
                processAndWrite(b, offset, length);
            } else if (bufferPosition + length > BUFFER_SIZE) {
                flushBuffer();
                System.arraycopy(b, offset, buffer, bufferPosition, length);
                bufferPosition += length;
            } else {
                System.arraycopy(b, offset, buffer, bufferPosition, length);
                bufferPosition += length;
            }
        }

        @Override
        public void write(int b) throws IOException {
            checkClosed();
            if (bufferPosition >= BUFFER_SIZE) {
                flushBuffer();
            }
            buffer[bufferPosition++] = (byte) b;
        }

        private void flushBuffer() throws IOException {
            if (bufferPosition > 0) {
                processAndWrite(buffer, 0, bufferPosition);
                bufferPosition = 0;
            }
        }

        private void processAndWrite(byte[] data, int offset, int length) throws IOException {
            int remaining = length;
            int dataOffset = offset;

            while (remaining > 0) {
                // Check if we need to start a new frame (using bit operations)
                int frameNumber = (int)(streamOffset >>> frameSizePower);
                if (frameNumber != currentFrameNumber) {
                    finalizeCurrentFrame();
                    totalFrames = Math.max(totalFrames, frameNumber + 1);
                    initializeFrameCipher(frameNumber, streamOffset & frameSizeMask);
                }

                // Calculate how much we can write in current frame
                int chunkSize = (int) Math.min(remaining, (frameSizeMask + 1) - (streamOffset & frameSizeMask));

                try {
                    byte[] encrypted = AesGcmCipherFactory.encryptWithoutTag(currentFrameOffset, currentCipher,
                                                                        slice(data, dataOffset, chunkSize), chunkSize);
                    // TODO: comment out this the above line and replace with OpensslNativeCipher.encryptUpdate. Both must be equivalent in fucntion
                    out.write(encrypted);

                    streamOffset += chunkSize;
                    currentFrameOffset += chunkSize;
                    remaining -= chunkSize;
                    dataOffset += chunkSize;
                } catch (Throwable t) {
                    throw new IOException("Encryption failed at offset " + streamOffset, t);
                }
            }
        }

        private byte[] slice(byte[] data, int offset, int length) {
            if (offset == 0 && length == data.length) {
                return data;
            }
            byte[] sliced = new byte[length];
            System.arraycopy(data, offset, sliced, 0, length);
            return sliced;
        }

        @Override
        public void close() throws IOException {
            IOException exception = null;

            try {
                checkClosed();
                flushBuffer();
                // Lucene writes footer here.
                // this will also flush the buffer.
                // Finalize current frame
                finalizeCurrentFrame();

                // Set final frame count in footer
                footer.setFrameCount(totalFrames);
//                footer.

                // Write footer with directory key for authentication
                out.write( footer.serialize(this.filePath, this.directoryKey));

                super.close();

                if(filePath != null) {
                    EncryptionCache encryptionCache = EncryptionCache.getInstance();
                    encryptionCache.putFooter(filePath.toAbsolutePath().toString(), footer);
                }

            } catch (IOException e) {
                exception = e;
            } finally {
                isClosed = true;
            }

            if (exception != null)
                throw exception;
        }

        private void checkClosed() throws IOException {
            if (isClosed) {
                throw new IOException("Output stream is already closed, this is unusual");
            }
        }

        /**
         * Initialize cipher for a new frame
         */
        private void initializeFrameCipher(int frameNumber, long offsetWithinFrame) {
            this.currentFrameNumber = frameNumber;
            this.currentFrameOffset = offsetWithinFrame;
            this.currentCipher = AesGcmCipherFactory.initializeFrameCipher(
                algorithm, provider, fileKey, directoryKey, footer.getMessageId(),
                frameNumber, offsetWithinFrame, filePathString
            );
            // todo; make this to use OpensslNativeCipher.initGCMCipher()  and comment out AesGcmCipherFactory.initializeFrameCipher line here
        }

        /**
         * Finalize current frame and collect GCM tag
         */
        private void finalizeCurrentFrame() throws IOException {
            AesGcmCipherFactory.finalizeFrameAndWriteTag(currentCipher, footer, out, currentFrameNumber);
            // todo: use OpenSSLNativeCipher.finalizeAndGetTag() method and comment out above line. Both methods should be quivalent
        }
    }
}
