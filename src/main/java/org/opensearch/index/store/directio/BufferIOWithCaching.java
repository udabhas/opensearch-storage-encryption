/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.directio;

import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_MASK;
import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.foreign.MemorySegment;
import java.nio.file.Path;
import java.security.Key;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.OutputStreamIndexOutput;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.PanamaNativeAccess;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheKey;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.cipher.AesGcmCipherFactory;
import org.opensearch.index.store.cipher.EncryptionAlgorithm;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.pool.MemorySegmentPool;
import org.opensearch.index.store.pool.Pool;

/**
 * An IndexOutput implementation that encrypts data before writing using native
 * OpenSSL AES-CTR.
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
@SuppressForbidden(reason = "temporary bypass")
public final class BufferIOWithCaching extends OutputStreamIndexOutput {
    private static final Logger LOGGER = LogManager.getLogger(BufferIOWithCaching.class);

    private static final int CHUNK_SIZE = CACHE_BLOCK_SIZE;
    private static final int BUFFER_SIZE = 65_536;

    private static final int BLOCK = 1 << CACHE_BLOCK_SIZE_POWER;
    private static final int BLOCK_MASK = BLOCK - 1;

    /**
     * Creates a new CryptoIndexOutput
     *
     * @param name The name of the output
     * @param path The path to write to
     * @param os The output stream
     * @param key The AES key (must be 32 bytes for AES-256)
     * @param iv The initialization vector (must be 16 bytes)
     * @throws IOException If there is an I/O error
     * @throws IllegalArgumentException If key or iv lengths are invalid
     */
    public BufferIOWithCaching(
        String name,
        Path path,
        OutputStream os,
        byte[] key,
        byte[] iv,
        Pool<MemorySegmentPool.SegmentHandle> memorySegmentPool,
        BlockCache<RefCountedMemorySegment> blockCache
    )
        throws IOException {
        super(
            "FSIndexOutput(path=\"" + path + "\")",
            name,
            new EncryptedOutputStream(os, path, key, iv, memorySegmentPool, blockCache),
            CHUNK_SIZE
        );
    }

    private static class EncryptedOutputStream extends FilterOutputStream {

        private final EncryptionFooter footer;
        private final byte[] directoryKey;
        private final Key fileKey;
        private final byte[] buffer;
        private final Path path;
        private final Pool<MemorySegmentPool.SegmentHandle> memorySegmentPool;
        private final BlockCache<RefCountedMemorySegment> blockCache;
        private final long frameSize;
        private final EncryptionAlgorithm algorithm;

        // Frame tracking
        private Cipher currentCipher;
        private int currentFrameNumber = 0;
        private long currentFrameOffset = 0;
        private int bufferPosition = 0;
        private long streamOffset = 0;
        private int totalFrames = 0;
        private boolean isClosed = false;

        EncryptedOutputStream(
            OutputStream os,
            Path path,
            byte[] key,
            byte[] iv,
            Pool<MemorySegmentPool.SegmentHandle> memorySegmentPool,
            BlockCache<RefCountedMemorySegment> blockCache
        ) {
            super(os);
            this.path = path;
            this.directoryKey = key;
            this.buffer = new byte[BUFFER_SIZE];
            this.memorySegmentPool = memorySegmentPool;
            this.blockCache = blockCache;
            this.frameSize = EncryptionMetadataTrailer.DEFAULT_FRAME_SIZE;
            this.algorithm = EncryptionAlgorithm.fromId((short) EncryptionMetadataTrailer.ALGORITHM_AES_256_GCM);
            
            this.footer = EncryptionFooter.generateNew(frameSize, (short) EncryptionMetadataTrailer.ALGORITHM_AES_256_GCM);
            
            // Derive file-specific key
            byte[] derivedKey = HkdfKeyDerivation.deriveAesKey(directoryKey, footer.getMessageId(), "file-encryption");
            this.fileKey = new javax.crypto.spec.SecretKeySpec(derivedKey, "AES");
            
            // Initialize first frame cipher
            initializeFrameCipher(0, 0);
        }

        @Override
        public void write(byte[] b, int offset, int length) throws IOException {
            checkClosed();
            if (b == null)
                throw new NullPointerException("Input buffer cannot be null");
            if (offset < 0 || length < 0 || offset + length > b.length) {
                throw new IndexOutOfBoundsException("Invalid offset or length");
            }
            if (length == 0)
                return;

            if (length >= BUFFER_SIZE) {
                flushBuffer();
                processAndWrite(path, b, offset, length);
                return;
            }

            if (bufferPosition + length > BUFFER_SIZE) {
                int partial = bufferPosition & BLOCK_MASK;
                if (partial != 0) {
                    int need = BLOCK - partial;
                    int take = Math.min(need, length);
                    System.arraycopy(b, offset, buffer, bufferPosition, take);
                    bufferPosition += take;
                    offset += take;
                    length -= take;
                }
                flushBuffer();
            }

            System.arraycopy(b, offset, buffer, bufferPosition, length);
            bufferPosition += length;
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
            if (bufferPosition == 0)
                return;

            final int flushable = (int) (bufferPosition & ~CACHE_BLOCK_MASK);
            if (flushable == 0)
                return;

            processAndWrite(path, buffer, 0, flushable);

            final int tail = bufferPosition - flushable;
            if (tail > 0) {
                System.arraycopy(buffer, flushable, buffer, 0, tail);
            }
            bufferPosition = tail;
        }

        private void forceFlushBuffer() throws IOException {
            if (bufferPosition > 0) {
                processAndWrite(path, buffer, 0, bufferPosition);
                bufferPosition = 0;
            }
        }

        private void processAndWrite(Path path, byte[] data, int arrayOffset, int length) throws IOException {
            int offsetInBuffer = 0;
            final MemorySegment full = MemorySegment.ofArray(data);

            while (offsetInBuffer < length) {
                long absoluteOffset = streamOffset + offsetInBuffer;
                long blockAlignedOffset = absoluteOffset & ~CACHE_BLOCK_MASK;
                int blockOffset = (int) (absoluteOffset & CACHE_BLOCK_MASK);
                int chunkLen = Math.min(length - offsetInBuffer, CACHE_BLOCK_SIZE - blockOffset);

                cacheBlockIfEligible(path, full, arrayOffset + offsetInBuffer, blockAlignedOffset, blockOffset, chunkLen);
                writeEncryptedChunk(data, arrayOffset + offsetInBuffer, chunkLen, absoluteOffset);
                offsetInBuffer += chunkLen;
            }

            streamOffset += length;
        }

        private void cacheBlockIfEligible(
            Path path,
            MemorySegment sourceData,
            int sourceOffset,
            long blockAlignedOffset,
            int blockOffset,
            int chunkLen
        ) {
            if (blockOffset == 0 && chunkLen == CACHE_BLOCK_SIZE) {
                try {
                    final MemorySegmentPool.SegmentHandle handle = memorySegmentPool.tryAcquire(5, TimeUnit.MILLISECONDS);
                    if (handle != null) {
                        final MemorySegment pooled = handle.segment();
                        final MemorySegment pooledSlice = pooled.asSlice(0, CACHE_BLOCK_SIZE);
                        MemorySegment.copy(sourceData, sourceOffset, pooledSlice, 0, CACHE_BLOCK_SIZE);

                        BlockCacheKey cacheKey = new FileBlockCacheKey(path, blockAlignedOffset);
                        RefCountedMemorySegment refSegment = new RefCountedMemorySegment(
                            pooled,
                            CACHE_BLOCK_SIZE,
                            seg -> handle.release()
                        );
                        blockCache.put(cacheKey, refSegment);
                    } else {
                        LOGGER.info("Failed to acquire from pool within specified timeout path={} {} ms", path, 5);
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    LOGGER.warn("Interrupted while acquiring segment for cache.");
                } catch (IllegalStateException e) {
                    LOGGER.debug("Failed to acquire segment from pool; skipping cache.");
                }
            }
        }

        private void writeEncryptedChunk(byte[] data, int offset, int length, long absoluteOffset
        ) throws IOException {
            int remaining = length;
            int dataOffset = offset;
            long currentOffset = absoluteOffset;

            while (remaining > 0) {
                int frameNumber = (int)(currentOffset / frameSize);
                if (frameNumber != currentFrameNumber) {
                    finalizeCurrentFrame();
                    totalFrames = Math.max(totalFrames, frameNumber + 1);
                    initializeFrameCipher(frameNumber, currentOffset % frameSize);
                }

                long frameEnd = (frameNumber + 1) * frameSize;
                int chunkSize = (int) Math.min(remaining, frameEnd - currentOffset);

                try {
                    byte[] encrypted = AesGcmCipherFactory.encryptWithoutTag(currentFrameOffset, currentCipher,
                                                                        slice(data, dataOffset, chunkSize), chunkSize);
                    out.write(encrypted);

                    currentOffset += chunkSize;
                    currentFrameOffset += chunkSize;
                    remaining -= chunkSize;
                    dataOffset += chunkSize;
                } catch (Throwable t) {
                    throw new IOException("Encryption failed at offset " + currentOffset, t);
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
                forceFlushBuffer();
                
                finalizeCurrentFrame();
                footer.setFrameCount(totalFrames);
                out.write(footer.serialize(this.directoryKey));

                super.close();
                loadFinalBlocksIntoCache();

                if (streamOffset > 32L * 1024 * 1024) {
                    String absolutePath = path.toAbsolutePath().toString();
                    Thread.startVirtualThread(() -> PanamaNativeAccess.dropFileCache(absolutePath));
                }

            } catch (IOException e) {
                exception = e;
            } finally {
                isClosed = true;
            }

            if (exception != null)
                throw exception;
        }

        private void loadFinalBlocksIntoCache() {
            try {
                if (streamOffset <= 0)
                    return;

                long finalBlockOffset = (streamOffset - 1) & ~CACHE_BLOCK_MASK;
                BlockCacheKey blockKey = new FileBlockCacheKey(path, finalBlockOffset);
                blockCache.getOrLoad(blockKey);

            } catch (IOException e) {
                LOGGER.debug("Failed to load final block into cache for path={}: {}", path, e.toString());
            }
        }

        private void checkClosed() throws IOException {
            if (isClosed) {
                throw new IOException("Output stream is already closed, this is unusual");
            }
        }

        private void initializeFrameCipher(int frameNumber, long offsetWithinFrame) {
            this.currentFrameNumber = frameNumber;
            this.currentFrameOffset = offsetWithinFrame;

            byte[] frameIV = AesCipherFactory.computeFrameIV(directoryKey, footer.getMessageId(),
                                                           frameNumber, offsetWithinFrame);

            this.currentCipher = algorithm.getEncryptionCipher(null);
            AesGcmCipherFactory.initCipher(this.currentCipher, this.fileKey, frameIV,
                                            Cipher.ENCRYPT_MODE, offsetWithinFrame);
        }

        private void finalizeCurrentFrame() throws IOException {
            if (currentCipher != null) {
                try {
                    byte[] finalData = AesGcmCipherFactory.finalizeAndGetTag(currentCipher);

                    if (finalData.length >= AesGcmCipherFactory.GCM_TAG_LENGTH) {
                        int encryptedLength = finalData.length - AesGcmCipherFactory.GCM_TAG_LENGTH;
                        if (encryptedLength > 0) {
                            out.write(finalData, 0, encryptedLength);
                        }

                        byte[] gcmTag = Arrays.copyOfRange(finalData, encryptedLength, finalData.length);
                        footer.addGcmTag(gcmTag);
                    }
                } catch (Throwable t) {
                    throw new IOException("Failed to finalize frame " + currentFrameNumber, t);
                }
            }
        }
    }
}