/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import javax.crypto.Cipher;

import org.apache.lucene.store.BufferedIndexInput;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.cipher.OpenSslNativeCipher;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * An IndexInput implementation that decrypts data for reading
 *
 * @opensearch.internal
 */
final class CryptoBufferedIndexInput extends BufferedIndexInput {

    private static final ByteBuffer EMPTY_BYTEBUFFER = ByteBuffer.allocate(0);
    private static final int CHUNK_SIZE = 16_384;

    private final FileChannel channel;
    private final boolean isClone;
    private final long off;
    private final long end;
    private Cipher cipher;
    private final KeyIvResolver keyResolver;

    private ByteBuffer tmpBuffer = EMPTY_BYTEBUFFER;

    public CryptoBufferedIndexInput(String resourceDesc, FileChannel fc, IOContext context, Cipher cipher, KeyIvResolver keyResolver)
        throws IOException {
        super(resourceDesc, context);
        this.channel = fc;
        this.off = 0L;
        this.end = fc.size();
        this.cipher = cipher;
        this.keyResolver = keyResolver;
        this.isClone = false;
    }

    public CryptoBufferedIndexInput(
        String resourceDesc,
        FileChannel fc,
        long off,
        long length,
        int bufferSize,
        Cipher originalCipher,
        KeyIvResolver keyResolver
    )
        throws IOException {
        super(resourceDesc, bufferSize);
        this.channel = fc;
        this.off = off;
        this.end = off + length;
        this.isClone = true;
        this.keyResolver = keyResolver;

        this.cipher = AesCipherFactory.getCipher(originalCipher.getProvider());
        AesCipherFactory.initCipher(cipher, keyResolver.getDataKey(), keyResolver.getIvBytes(), Cipher.DECRYPT_MODE, off);
    }

    @Override
    public void close() throws IOException {
        if (!isClone) {
            channel.close();
        }
    }

    @Override
    public CryptoBufferedIndexInput clone() {
        CryptoBufferedIndexInput clone = (CryptoBufferedIndexInput) super.clone();
        clone.tmpBuffer = EMPTY_BYTEBUFFER;
        clone.cipher = AesCipherFactory.getCipher(cipher.getProvider());
        AesCipherFactory
            .initCipher(clone.cipher, keyResolver.getDataKey(), keyResolver.getIvBytes(), Cipher.DECRYPT_MODE, getFilePointer() + off);
        return clone;
    }

    @Override
    public IndexInput slice(String sliceDescription, long offset, long length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > this.length()) {
            throw new IllegalArgumentException(
                "slice() " + sliceDescription + " out of bounds: offset=" + offset + ", length=" + length + ", fileLength=" + this.length()
            );
        }
        return new CryptoBufferedIndexInput(
            getFullSliceDescription(sliceDescription),
            channel,
            off + offset,
            length,
            getBufferSize(),
            cipher,
            keyResolver
        );
    }

    @Override
    public long length() {
        return end - off;
    }

    @Override
    protected void readInternal(ByteBuffer b) throws IOException {
        long pos = getFilePointer() + off;
        if (pos + b.remaining() > end) {
            throw new EOFException("read past EOF: pos=" + pos + ", end=" + end);
        }

        int readLength = b.remaining();
        while (readLength > 0) {
            final int toRead = Math.min(CHUNK_SIZE, readLength);
            b.limit(b.position() + toRead);
            final int bytesRead = read(b, pos);

            if (bytesRead < 0) {
                throw new EOFException("Unexpected EOF while reading decrypted data at pos=" + pos);
            }

            pos += bytesRead;
            readLength -= bytesRead;
        }
    }

    @SuppressForbidden(reason = "FileChannel#read is efficient and used intentionally")
    private int read(ByteBuffer dst, long position) throws IOException {
        int toRead = dst.remaining();
        long blockAlignedPos = (position / 16) * 16;
        int prefixDiscard = (int) (position % 16);

        // Read enough blocks to cover the requested data
        int blocksNeeded = (prefixDiscard + toRead + 15) / 16;
        int paddedRead = blocksNeeded * 16;

        if (tmpBuffer == EMPTY_BYTEBUFFER || tmpBuffer.capacity() < paddedRead) {
            tmpBuffer = ByteBuffer.allocate(paddedRead);
        }

        tmpBuffer.clear().limit(paddedRead);
        int bytesRead = channel.read(tmpBuffer, blockAlignedPos);
        if (bytesRead <= 0) {
            return -1;
        }

        tmpBuffer.flip();
        byte[] encryptedData = new byte[bytesRead];
        tmpBuffer.get(encryptedData);

        try {
            byte[] decrypted = OpenSslNativeCipher
                .decryptCTR(keyResolver.getDataKey().getEncoded(), keyResolver.getIvBytes(), encryptedData, blockAlignedPos);

            // byte[] decrypted = JavaNativeCipher.decryptCTRJava(
            // keyResolver.getDataKey().getEncoded(),
            // keyResolver.getIvBytes(),
            // encryptedData,
            // blockAlignedPos
            // );

            // Copy the requested bytes, handling partial blocks correctly
            int availableBytes = decrypted.length - prefixDiscard;
            int actualBytes = Math.min(availableBytes, toRead);

            if (actualBytes > 0) {
                dst.put(decrypted, prefixDiscard, actualBytes);
            }

            return actualBytes > 0 ? actualBytes : -1;
        } catch (Throwable t) {
            throw new IOException("Failed to decrypt block at position " + position, t);
        }
    }

    @Override
    protected void seekInternal(long pos) throws IOException {
        if (pos > length()) {
            throw new EOFException("seek past EOF: pos=" + pos + ", length=" + length());
        }
    }
}
