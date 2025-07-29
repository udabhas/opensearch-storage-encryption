/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import static org.opensearch.index.store.cipher.AesCipherFactory.ALGORITHM;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.BufferedIndexInput;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.HkdfKeyDerivation;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * An IndexInput implementation that decrypts data for reading
 *
 * @opensearch.internal
 */
final class CryptoBufferedIndexInput extends BufferedIndexInput {
    private static final byte[] ZERO_SKIP = new byte[AesCipherFactory.AES_BLOCK_SIZE_BYTES];
    private static final ByteBuffer EMPTY_BYTEBUFFER = ByteBuffer.allocate(0);
    private static final int CHUNK_SIZE = 16_384;

    private final FileChannel channel;
    private final boolean isClone;
    private final long off;
    private final long end;
    private final KeyIvResolver keyResolver;
    private final SecretKeySpec keySpec;

    private ByteBuffer tmpBuffer = EMPTY_BYTEBUFFER;

    public CryptoBufferedIndexInput(String resourceDesc, FileChannel fc, IOContext context, KeyIvResolver keyResolver) throws IOException {
        super(resourceDesc, context);
        this.channel = fc;
        this.off = 0L;
        this.end = fc.size();
        this.keyResolver = keyResolver;
        this.isClone = false;
        
        // Read footer and derive file-specific key
        EncryptionFooter footer = readFooterFromFile();
        byte[] directoryKey = keyResolver.getDataKey().getEncoded();
        byte[] derivedKey = HkdfKeyDerivation.deriveAesKey(directoryKey, footer.getMessageId(), "file-encryption");
        this.keySpec = new SecretKeySpec(derivedKey, ALGORITHM);
    }

    public CryptoBufferedIndexInput(String resourceDesc, FileChannel fc, long off, long length, int bufferSize, KeyIvResolver keyResolver, SecretKeySpec keySpec)
        throws IOException {
        super(resourceDesc, bufferSize);
        this.channel = fc;
        this.off = off;
        this.end = off + length;
        this.isClone = true;
        this.keyResolver = keyResolver;
        this.keySpec = keySpec;  // Reuse keySpec from main file
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
            keyResolver,
            keySpec  // Pass the already-derived keySpec
        );
    }

    @Override
    public long length() {
        // Exclude footer from logical file length (only for main file, not slices)
        if (isClone) {
            return end - off;  // Slices use exact length passed in
        } else {
            return end - off - EncryptionFooter.FOOTER_SIZE;  // Main file excludes footer
        }
    }

    @SuppressForbidden(reason = "FileChannel#read is efficient and used intentionally")
    private int read(ByteBuffer dst, long position) throws IOException {

        // initialize buffer lazy because Lucene may open input slices and clones ahead but never use them
        // see org.apache.lucene.store.BufferedIndexInput
        if (tmpBuffer == EMPTY_BYTEBUFFER) {
            tmpBuffer = ByteBuffer.allocate(CHUNK_SIZE);
        }

        tmpBuffer.clear().limit(dst.remaining());
        int bytesRead = channel.read(tmpBuffer, position);
        if (bytesRead == -1) {
            return -1;
        }

        tmpBuffer.flip();

        try {
            Cipher cipher = AesCipherFactory.CIPHER_POOL.get();

            byte[] ivCopy = AesCipherFactory.computeOffsetIVForAesGcmEncrypted(keyResolver.getIvBytes(), position);

            cipher.init(Cipher.DECRYPT_MODE, this.keySpec, new IvParameterSpec(ivCopy));

            if (position % AesCipherFactory.AES_BLOCK_SIZE_BYTES > 0) {
                cipher.update(ZERO_SKIP, 0, (int) (position % AesCipherFactory.AES_BLOCK_SIZE_BYTES));
            }

            return (end - position > bytesRead) ? cipher.update(tmpBuffer, dst) : cipher.doFinal(tmpBuffer, dst);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException
            | InvalidKeyException ex) {
            throw new IOException("Failed to decrypt block at position " + position, ex);
        }
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

    @Override
    protected void seekInternal(long pos) throws IOException {
        if (pos > length()) {
            throw new EOFException("seek past EOF: pos=" + pos + ", length=" + length());
        }
    }
    
    /**
     * Read encryption footer from end of file
     */
    private EncryptionFooter readFooterFromFile() throws IOException {
        long fileSize = channel.size();
        if (fileSize < EncryptionFooter.FOOTER_SIZE) {
            throw new IOException("File too small to contain encryption footer");
        }
        
        ByteBuffer footerBuffer = ByteBuffer.allocate(EncryptionFooter.FOOTER_SIZE);
        int bytesRead = channel.read(footerBuffer, fileSize - EncryptionFooter.FOOTER_SIZE);
        
        if (bytesRead != EncryptionFooter.FOOTER_SIZE) {
            throw new IOException("Failed to read complete footer");
        }
        
        return EncryptionFooter.deserialize(footerBuffer.array());
    }
}
