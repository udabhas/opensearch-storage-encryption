/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.mmap;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.AlreadyClosedException;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.RandomAccessInput;
import org.apache.lucene.util.ArrayUtil;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.MemorySegmentDecryptor;
import org.opensearch.index.store.concurrency.AtomicBitSet;
import org.opensearch.index.store.key.HkdfKeyDerivation;

@SuppressForbidden(reason = "temporary bypass")
@SuppressWarnings("preview")
public class LazyDecryptedMemorySegmentIndexInput extends IndexInput implements RandomAccessInput {

    private static final Logger LOGGER = LogManager.getLogger(LazyDecryptedMemorySegmentIndexInput.class);

    static final ValueLayout.OfByte LAYOUT_BYTE = ValueLayout.JAVA_BYTE;
    static final ValueLayout.OfShort LAYOUT_LE_SHORT = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfInt LAYOUT_LE_INT = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfLong LAYOUT_LE_LONG = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfFloat LAYOUT_LE_FLOAT = ValueLayout.JAVA_FLOAT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    final long resourceLength;
    final long chunkSizeMask;
    final int chunkSizePower;
    final Arena arena;
    final MemorySegment[] segments;
    final byte[] fileKey;
    final byte[] messageId;
    final long frameSize;
    final short algorithmId;
    final byte[] directoryKey;
    final AtomicBitSet decryptedPages;
    final AtomicBitSet inProgressPages;
    final String resourceDescription;
    final long decryptionBaseOffset;

    int curSegmentIndex = -1;
    MemorySegment curSegment; // redundant for speed: segments[curSegmentIndex], also marker if closed!
    long curPosition; // relative to curSegment, not globally

    public static LazyDecryptedMemorySegmentIndexInput newInstance(
        String resourceDescription,
        Arena arena,
        MemorySegment[] segments,
        long resourceLength,
        int chunkSizePower,
        byte[] messageId,
        long frameSize,
        short algorithmId,
        byte[] directoryKey
    ) {
        // Derive file-specific key from directory key and messageId
        byte[] fileKey = HkdfKeyDerivation.deriveAesKey(directoryKey, messageId, "file-encryption");

        long totalPages = (resourceLength + PanamaNativeAccess.getPageSize() - 1) / PanamaNativeAccess.getPageSize();
        AtomicBitSet decryptedPages = new AtomicBitSet(totalPages);
        AtomicBitSet inProgressPages = new AtomicBitSet(totalPages);

        assert Arrays.stream(segments).map(MemorySegment::scope).allMatch(arena.scope()::equals);

        if (segments.length == 1) {
            return new SingleSegmentImpl(
                resourceDescription,
                arena,
                segments[0],
                resourceLength,
                chunkSizePower,
                fileKey,
                messageId,
                frameSize,
                algorithmId,
                directoryKey,
                decryptedPages,
                inProgressPages,
                0L
            );
        } else {
            return new MultiSegmentImpl(
                resourceDescription,
                arena,
                segments,
                0,
                resourceLength,
                chunkSizePower,
                fileKey,
                messageId,
                frameSize,
                algorithmId,
                directoryKey,
                decryptedPages,
                inProgressPages,
                0L
            );
        }

    }

    private LazyDecryptedMemorySegmentIndexInput(
        String resourceDescription,
        Arena arena,
        MemorySegment[] segments,
        long resourceLength,
        int chunkSizePower,
        byte[] fileKey,
        byte[] messageId,
        long frameSize,
        short algorithmId,
        byte[] directoryKey,
        AtomicBitSet decryptedPages,
        AtomicBitSet inProgressPages,
        long decryptionBaseOffset
    ) {
        super(resourceDescription);
        this.arena = arena;
        this.segments = segments;
        this.resourceLength = resourceLength;
        this.chunkSizePower = chunkSizePower;
        this.chunkSizeMask = (1L << chunkSizePower) - 1L;
        this.curSegment = segments[0];
        this.fileKey = fileKey;
        this.messageId = messageId;
        this.frameSize = frameSize;
        this.algorithmId = algorithmId;
        this.directoryKey = directoryKey;
        this.decryptedPages = decryptedPages;
        this.inProgressPages = inProgressPages;
        this.resourceDescription = resourceDescription;
        this.decryptionBaseOffset = decryptionBaseOffset;
    }

    void ensureOpen() {
        if (curSegment == null) {
            throw alreadyClosed(null);
        }
    }

    protected long getDecryptionOffset() {
        // Use the existing getFilePointer() which gives us position relative to this input
        return getFilePointer() + decryptionBaseOffset;
    }

    protected long getDecryptionOffset(long pos) {
        // pos is relative to this input, add base offset for absolute position
        return pos + decryptionBaseOffset;
    }

    @SuppressWarnings("unused")
    private static void decryptAndProtectPageByPage(
        String resourceDescription,
        long resourceLength,
        AtomicBitSet decryptedPages,
        AtomicBitSet inProgressPages,
        long addr,
        long length,
        long fileOffset,
        byte[] key,
        byte[] iv
    ) throws IOException {
        // lucene may open zero data files.
        // very important.
        if (length == 0) {
            return;
        }

        int osPageSize = PanamaNativeAccess.getPageSize();
        long alignedAddr = addr & ~(osPageSize - 1);
        long requestEnd = addr + length;
        long alignedEnd = ((requestEnd + osPageSize - 1) & ~(osPageSize - 1));
        long baseFileOffset = fileOffset - (addr - alignedAddr);

        int pageCount = 0;
        int pagesAlreadyDecrypted = 0;

        long startTime = System.nanoTime();

        for (long pageAddr = alignedAddr; pageAddr < alignedEnd; pageAddr += osPageSize) {
            long pageFileOffset = baseFileOffset + (pageAddr - alignedAddr);
            long pageFileKey = pageFileOffset & ~(osPageSize - 1);
            long pageNum = pageFileKey / osPageSize;

            // Fast-path: page already decrypted
            if (decryptedPages.get(pageNum)) {
                LOGGER.trace("Page already decrypted: resource={}, pageNum={}", resourceDescription, pageNum);
                pagesAlreadyDecrypted++;
                continue;
            }

            long pageStart = Math.max(pageAddr, addr);
            long pageEnd = Math.min(pageAddr + osPageSize, addr + length);

            if (pageStart >= pageEnd) {
                LOGGER.debug("Skipping page outside request: pageNum={}", pageNum);
                continue;
            }

            // Try to claim exclusive access to this page
            if (inProgressPages.getAndSet(pageNum)) {
                // Another thread is decrypting this page
                continue;
            }

            // Double-check after claiming (another thread might have finished)
            if (decryptedPages.get(pageNum)) {
                pagesAlreadyDecrypted++;
                inProgressPages.clear(pageNum);
                continue;
            }

            try {
                MemorySegmentDecryptor.decryptInPlace(pageAddr, osPageSize, key, iv, pageFileOffset);
                decryptedPages.getAndSet(pageNum);
                pageCount++;

                LOGGER
                    .debug(
                        "Successfully decrypted page: resource={}, pageNum={}, pageAddr=0x{}, pageFileOffset={}",
                        resourceDescription,
                        pageNum,
                        Long.toHexString(pageAddr),
                        pageFileOffset
                    );

            } catch (Exception e) {
                String errorMsg = String
                    .format(
                        "Decryption failed: page=0x%x, pageNum=%d, fileOffset=%d, resource=%s",
                        pageAddr,
                        pageNum,
                        pageFileOffset,
                        resourceDescription
                    );
                throw new IOException(errorMsg, e);
            } finally {
                // Always release the exclusive access claim
                inProgressPages.clear(pageNum);
            }
        }

        long endTime = System.nanoTime(); //
        long durationMicros = (endTime - startTime) / 1_000;

        LOGGER
            .debug(
                "Lazy decryption {} of cfs files (size: {} MB) slice length {} KB: pages touched {}, pages skipped {}, took {} us",
                resourceDescription,
                resourceLength / 1_048_576.0,
                length / 1024,
                pageCount,
                pagesAlreadyDecrypted,
                durationMicros
            );

    }

    private static void decryptAndProtectFrameBased(
        String resourceDescription,
        long resourceLength,
        AtomicBitSet decryptedPages,
        AtomicBitSet inProgressPages,
        long addr,
        long length,
        long fileOffset,
        byte[] fileKey,
        byte[] directoryKey,
        byte[] messageId,
        long frameSize
    ) throws IOException {

        if (length == 0) {
            return;
        }

        int osPageSize = PanamaNativeAccess.getPageSize();
        long alignedAddr = addr & ~(osPageSize - 1);
        long requestEnd = addr + length;
        long alignedEnd = ((requestEnd + osPageSize - 1) & ~(osPageSize - 1));
        long baseFileOffset = fileOffset - (addr - alignedAddr);

        long currentPageAddr = alignedAddr;

        int pageCount = 0;
        long startTime = System.nanoTime();

        while (currentPageAddr < alignedEnd) {
            long pageFileOffset = baseFileOffset + (currentPageAddr - alignedAddr);
            long pageFileKey = pageFileOffset & ~(osPageSize - 1);
            long pageNum = pageFileKey / osPageSize;

            // Skip if already decrypted
            if (decryptedPages.get(pageNum)) {
                currentPageAddr += osPageSize;
                continue;
            }

            // Found a non decrypted page - start collecting contiguous batch
            long batchStartAddr = currentPageAddr;
            long batchStartFileOffset = pageFileOffset;
            List<Long> batchPageNumbers = new ArrayList<>();

            // Inner while loop: collect all contiguous unencrypted pages
            while (currentPageAddr < alignedEnd) {
                pageFileOffset = baseFileOffset + (currentPageAddr - alignedAddr);
                pageFileKey = pageFileOffset & ~(osPageSize - 1);
                pageNum = pageFileKey / osPageSize;

                if (decryptedPages.get(pageNum))
                    break;
                if (inProgressPages.getAndSet(pageNum))
                    break;

                batchPageNumbers.add(pageNum);
                currentPageAddr += osPageSize;
            }

            if (batchPageNumbers.isEmpty())
                continue;
            // Decrypt the entire batch at once
            long batchSize = batchPageNumbers.size() * osPageSize;

            try {
                // Use frame-based decryption
                MemorySegmentDecryptor.decryptInPlaceFrameBased(batchStartAddr, batchSize, fileKey, directoryKey, messageId, frameSize, batchStartFileOffset);

                // Mark all pages as decrypted
                for (Long page : batchPageNumbers) {
                    decryptedPages.getAndSet(page);
                }
            } catch (Exception e) {
                throw new IOException(e);
            } finally {
                // Release all claimed pages
                for (Long page : batchPageNumbers) {
                    inProgressPages.clear(page);
                }
            }

            pageCount += batchPageNumbers.size();
        }

        long endTime = System.nanoTime();
        long durationMicros = (endTime - startTime) / 1_000;

        LOGGER
            .debug(
                "Lazy frame-based decryption {} of files (size: {} MB) slice length {} bytes: pages touched {}, took {} us",
                resourceDescription,
                resourceLength / 1_048_576.0,
                length,
                pageCount,
                durationMicros
            );
    }
    
    private static void decryptAndProtect(
        String resourceDescription,
        long resourceLength,
        AtomicBitSet decryptedPages,
        AtomicBitSet inProgressPages,
        long addr,
        long length,
        long fileOffset,
        byte[] key,
        byte[] iv
    ) throws IOException {

        if (length == 0) {
            return;
        }

        int osPageSize = PanamaNativeAccess.getPageSize();
        long alignedAddr = addr & ~(osPageSize - 1);
        long requestEnd = addr + length;
        long alignedEnd = ((requestEnd + osPageSize - 1) & ~(osPageSize - 1));
        long baseFileOffset = fileOffset - (addr - alignedAddr);

        long currentPageAddr = alignedAddr;

        int pageCount = 0;
        long startTime = System.nanoTime();

        while (currentPageAddr < alignedEnd) {
            long pageFileOffset = baseFileOffset + (currentPageAddr - alignedAddr);
            long pageFileKey = pageFileOffset & ~(osPageSize - 1);
            long pageNum = pageFileKey / osPageSize;

            // Skip if already decrypted
            if (decryptedPages.get(pageNum)) {
                currentPageAddr += osPageSize;
                continue;
            }

            // Found a non decrypted page - start collecting contiguous batch
            long batchStartAddr = currentPageAddr;
            long batchStartFileOffset = pageFileOffset;
            List<Long> batchPageNumbers = new ArrayList<>();

            // Inner while loop: collect all contiguous unencrypted pages
            while (currentPageAddr < alignedEnd) {
                pageFileOffset = baseFileOffset + (currentPageAddr - alignedAddr);
                pageFileKey = pageFileOffset & ~(osPageSize - 1);
                pageNum = pageFileKey / osPageSize;

                if (decryptedPages.get(pageNum))
                    break;
                if (inProgressPages.getAndSet(pageNum))
                    break;

                batchPageNumbers.add(pageNum);
                currentPageAddr += osPageSize;
            }

            if (batchPageNumbers.isEmpty())
                continue;
            // Decrypt the entire batch at once
            long batchSize = batchPageNumbers.size() * osPageSize;

            try {

                MemorySegmentDecryptor.decryptInPlace(batchStartAddr, batchSize, key, iv, batchStartFileOffset);

                // Mark all pages as decrypted
                for (Long page : batchPageNumbers) {
                    decryptedPages.getAndSet(page);
                }
            }
            // Very important....
            // TODO Handle failures for each failed page.
            catch (Exception e) {
                // decryptedPages.clear(pageNum);
                // String errorMsg = String
                // .format(
                // "Decryption failed: page=0x%x, pageNum=%d, fileOffset=%d, resource=%s",
                // pageAddr,
                // pageNum,
                // pageFileOffset,
                // resourceDescription
                // );
                throw new IOException(e);
            } finally {
                // Release all claimed pages
                for (Long page : batchPageNumbers) {
                    inProgressPages.clear(page);
                }
            }

            pageCount += batchPageNumbers.size();

        }

        long endTime = System.nanoTime(); //
        long durationMicros = (endTime - startTime) / 1_000;

        LOGGER
            .debug(
                "Lazy decryption {} of files (size: {} MB) slice length {} bytes: pages touched {}, took {} us",
                resourceDescription,
                resourceLength / 1_048_576.0,
                length,
                pageCount,
                durationMicros
            );

    }

    // the unused parameter is just to silence javac about unused variables
    RuntimeException handlePositionalIOOBE(RuntimeException unused, String action, long pos) throws IOException {
        if (pos < 0L) {
            return new IllegalArgumentException(action + " negative position (pos=" + pos + "): " + this);
        } else {
            throw new EOFException(action + " past EOF (pos=" + pos + "): " + this);
        }
    }

    // the unused parameter is just to silence javac about unused variables
    AlreadyClosedException alreadyClosed(RuntimeException unused) {
        return new AlreadyClosedException("Already closed: " + this);
    }

    @Override
    public final byte readByte() throws IOException {
        try {
            // Decrypt current byte before reading
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                1,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            final byte v = curSegment.get(LAYOUT_BYTE, curPosition);
            curPosition++;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            try {
                do {
                    curSegmentIndex++;
                    if (curSegmentIndex >= segments.length) {
                        throw new EOFException("read past EOF: " + this);
                    }
                    curSegment = segments[curSegmentIndex];
                    curPosition = 0L;
                } while (curSegment.byteSize() == 0L);

                // Decrypt the byte in the new segment
                long addr = curSegment.address() + curPosition;
                long fileOffset = getDecryptionOffset();

                decryptAndProtectFrameBased(
                    this.resourceDescription,
                    this.resourceLength,
                    this.decryptedPages,
                    this.inProgressPages,
                    addr,
                    1,
                    fileOffset,
                    this.fileKey,
                    this.directoryKey,
                    this.messageId,
                    this.frameSize
                );

                final byte v = curSegment.get(LAYOUT_BYTE, curPosition);
                curPosition++;
                return v;
            } catch (NullPointerException | IllegalStateException e2) {
                throw alreadyClosed(e2);
            } catch (IOException e2) {
                throw new IOException("Decryption failed", e2);
            }
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    @Override
    public final void readBytes(byte[] b, int offset, int len) throws IOException {
        try {
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            // Decrypt the entire region we're about to read
            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                len,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            MemorySegment.copy(curSegment, LAYOUT_BYTE, curPosition, b, offset, len);
            curPosition += len;
        } catch (IndexOutOfBoundsException e) {
            readBytesBoundary(b, offset, len);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption or read failed", e);
        }
    }

    private void readBytesBoundary(byte[] b, int offset, int len) throws IOException {
        long startFileOffset = getDecryptionOffset(); // CHANGE: Use getDecryptionOffset() instead of getFilePointer()
        int originalLen = len;
        try {
            long curAvail = curSegment.byteSize() - curPosition;
            while (len > curAvail) {
                long addr = curSegment.address() + curPosition;
                long fileOffset = startFileOffset + (originalLen - len); // Calculate relative offset
                decryptAndProtectFrameBased(
                    this.resourceDescription,
                    this.resourceLength,
                    this.decryptedPages,
                    this.inProgressPages,
                    addr,
                    curAvail,
                    fileOffset,
                    this.fileKey,
                    this.directoryKey,
                    this.messageId,
                    this.frameSize
                );
                MemorySegment.copy(curSegment, LAYOUT_BYTE, curPosition, b, offset, (int) curAvail);
                len -= curAvail;
                offset += curAvail;
                curSegmentIndex++;
                if (curSegmentIndex >= segments.length) {
                    throw new EOFException("read past EOF: " + this);
                }
                curSegment = segments[curSegmentIndex];
                curPosition = 0L;
                curAvail = curSegment.byteSize();
            }

            long addr = curSegment.address() + curPosition;
            long fileOffset = startFileOffset + (originalLen - len);
            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                len,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );
            MemorySegment.copy(curSegment, LAYOUT_BYTE, curPosition, b, offset, len);
            curPosition += len;
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    /**
    * Helper method to decrypt current segment remainder and next segment for
    * boundary crossing reads
    */
    private void decryptForBoundaryCrossing() throws IOException {
        // Decrypt remainder of current segment
        long currentSegmentRemaining = curSegment.byteSize() - curPosition;
        if (currentSegmentRemaining > 0) {
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset(); // CHANGE: Use getDecryptionOffset()
            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                currentSegmentRemaining,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );
        }

        // Decrypt entire next segment if it exists
        if (curSegmentIndex + 1 < segments.length) {
            MemorySegment nextSegment = segments[curSegmentIndex + 1];
            long addr = nextSegment.address();
            // CHANGE: Calculate absolute file offset for next segment
            long fileOffset = decryptionBaseOffset + ((long) (curSegmentIndex + 1) << chunkSizePower);
            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                nextSegment.byteSize(),
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );
        }
    }

    @Override
    public void readInts(int[] dst, int offset, int length) throws IOException {
        try {
            // Decrypt the range we're about to read
            long totalBytes = Integer.BYTES * (long) length;
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                totalBytes,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            MemorySegment.copy(curSegment, LAYOUT_LE_INT, curPosition, dst, offset, length);
            curPosition += totalBytes;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException iobe) {
            // Crossing segment boundaries - decrypt current segment remainder and next segment
            // Decrypt remainder of current segment
            decryptForBoundaryCrossing();
            super.readInts(dst, offset, length);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public void readLongs(long[] dst, int offset, int length) throws IOException {
        try {
            // Decrypt the range we're about to read
            long totalBytes = Long.BYTES * (long) length;
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                totalBytes,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            MemorySegment.copy(curSegment, LAYOUT_LE_LONG, curPosition, dst, offset, length);
            curPosition += totalBytes;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException iobe) {
            // Crossing segment boundaries - decrypt segments then delegate to super
            decryptForBoundaryCrossing();
            super.readLongs(dst, offset, length);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public void readFloats(float[] dst, int offset, int length) throws IOException {
        try {
            // Decrypt the range we're about to read
            long totalBytes = Float.BYTES * (long) length;
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                totalBytes,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            MemorySegment.copy(curSegment, LAYOUT_LE_FLOAT, curPosition, dst, offset, length);
            curPosition += totalBytes;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException iobe) {
            // Crossing segment boundaries - decrypt segments then delegate to super
            decryptForBoundaryCrossing();
            super.readFloats(dst, offset, length);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final short readShort() throws IOException {
        try {
            // Decrypt the range we're about to read
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                Short.BYTES,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            final short v = curSegment.get(LAYOUT_LE_SHORT, curPosition);
            curPosition += Short.BYTES;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            return super.readShort();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final int readInt() throws IOException {
        try {
            // Decrypt the range we're about to read
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                Integer.BYTES,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            final int v = curSegment.get(LAYOUT_LE_INT, curPosition);
            curPosition += Integer.BYTES;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            return super.readInt();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final long readLong() throws IOException {
        try {
            // Decrypt the range we're about to read
            long addr = curSegment.address() + curPosition;
            long fileOffset = getDecryptionOffset();

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                Long.BYTES,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            final long v = curSegment.get(LAYOUT_LE_LONG, curPosition);
            curPosition += Long.BYTES;
            return v;
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException e) {
            return super.readLong();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public long getFilePointer() {
        ensureOpen();
        return (((long) curSegmentIndex) << chunkSizePower) + curPosition;
    }

    @Override
    public void seek(long pos) throws IOException {
        ensureOpen();
        // we use >> here to preserve negative, so we will catch AIOOBE,
        // in case pos + offset overflows.
        final int si = (int) (pos >> chunkSizePower);
        try {
            if (si != curSegmentIndex) {
                final MemorySegment seg = segments[si];
                // write values, on exception all is unchanged
                this.curSegmentIndex = si;
                this.curSegment = seg;
            }
            this.curPosition = Objects.checkIndex(pos & chunkSizeMask, curSegment.byteSize() + 1);
        } catch (IndexOutOfBoundsException e) {
            throw handlePositionalIOOBE(e, "seek", pos);
        }
    }

    @Override
    public byte readByte(long pos) throws IOException {
        try {
            final int si = (int) (pos >> chunkSizePower);
            final long segmentOffset = pos & chunkSizeMask;

            // Calculate address and decrypt the single byte
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = getDecryptionOffset(pos);
            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                1,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            return segments[si].get(LAYOUT_BYTE, segmentOffset);
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    // used only by random access methods to handle reads across boundaries
    private void setPos(long pos, int si) throws IOException {
        try {
            final MemorySegment seg = segments[si];
            // write values, on exception above all is unchanged
            this.curPosition = pos & chunkSizeMask;
            this.curSegmentIndex = si;
            this.curSegment = seg;
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public short readShort(long pos) throws IOException {

        final int si = (int) (pos >> chunkSizePower);
        final long segmentOffset = pos & chunkSizeMask;

        try {
            // Calculate address and decrypt the 2 bytes for short
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = getDecryptionOffset(pos);
            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                2,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            return segments[si].get(LAYOUT_LE_SHORT, segmentOffset);
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException ioobe) {
            // either it's a boundary, or read past EOF, fall back:
            setPos(pos, si);
            return readShort();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }

    }

    @Override
    public int readInt(long pos) throws IOException {
        final int si = (int) (pos >> chunkSizePower);
        final long segmentOffset = pos & chunkSizeMask;

        try {
            // Add decryption before reading
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = getDecryptionOffset(pos);

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                Integer.BYTES,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            return segments[si].get(LAYOUT_LE_INT, segmentOffset);
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException ioobe) {
            // either it's a boundary, or read past EOF, fall back:
            setPos(pos, si);
            return readInt();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    @Override
    public long readLong(long pos) throws IOException {
        final int si = (int) (pos >> chunkSizePower);
        final long segmentOffset = pos & chunkSizeMask;

        try {
            // Add decryption before reading
            long addr = segments[si].address() + segmentOffset;
            long fileOffset = getDecryptionOffset(pos);

            decryptAndProtectFrameBased(
                this.resourceDescription,
                this.resourceLength,
                this.decryptedPages,
                this.inProgressPages,
                addr,
                Long.BYTES,
                fileOffset,
                this.fileKey,
                this.directoryKey,
                this.messageId,
                this.frameSize
            );

            return segments[si].get(LAYOUT_LE_LONG, segmentOffset);
        } catch (@SuppressWarnings("unused") IndexOutOfBoundsException ioobe) {
            // either it's a boundary, or read past EOF, fall back:
            setPos(pos, si);
            return readLong();
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        } catch (IOException e) {
            throw new IOException("Decryption failed", e);
        }
    }

    @Override
    public final long length() {
        return resourceLength;
    }

    @Override
    public final LazyDecryptedMemorySegmentIndexInput clone() {
        final LazyDecryptedMemorySegmentIndexInput clone = buildSlice((String) null, 0L, this.resourceLength);
        try {
            clone.seek(getFilePointer());
        } catch (IOException ioe) {
            throw new AssertionError(ioe);
        }

        return clone;
    }

    /**
     * Creates a slice of this index input, with the given description, offset,
     * and length. The slice is seeked to the beginning.
     */
    @Override
    public final LazyDecryptedMemorySegmentIndexInput slice(String sliceDescription, long offset, long length) {
        if (offset < 0 || length < 0 || offset + length > this.resourceLength) {
            throw new IllegalArgumentException(
                "slice() "
                    + sliceDescription
                    + " out of bounds: offset="
                    + offset
                    + ",length="
                    + length
                    + ",fileLength="
                    + this.resourceLength
                    + ": "
                    + this
            );
        }

        return buildSlice(sliceDescription, offset, length);
    }

    /**
     * Builds the actual sliced IndexInput (may apply extra offset in
     * subclasses). *
     */
    LazyDecryptedMemorySegmentIndexInput buildSlice(String sliceDescription, long offset, long length) {
        ensureOpen();

        // Calculate the absolute file position where this slice starts
        // This is crucial for decryption - we need to know where in the original file we are
        final long sliceAbsoluteOffset = this.decryptionBaseOffset + offset;

        final long sliceEnd = offset + length;
        final int startIndex = (int) (offset >>> chunkSizePower);
        final int endIndex = (int) (sliceEnd >>> chunkSizePower);

        // Copy the relevant segments
        final MemorySegment slices[] = ArrayUtil.copyOfSubArray(segments, startIndex, endIndex + 1);

        // Set the last segment's limit for the sliced view
        slices[slices.length - 1] = slices[slices.length - 1].asSlice(0L, sliceEnd & chunkSizeMask);

        // Convert offset to position within the first segment
        final long segmentOffset = offset & chunkSizeMask;

        LOGGER
            .debug(
                "Building slice: description={}, parentOffset={}, length={}, " + "absoluteFileOffset={}, segmentOffset={}, startIndex={}",
                sliceDescription,
                offset,
                length,
                sliceAbsoluteOffset,
                segmentOffset,
                startIndex
            );

        final String newResourceDescription = getFullSliceDescription(sliceDescription);

        if (slices.length == 1) {
            return new SingleSegmentImpl(
                newResourceDescription,
                null, // clones don't have an Arena, as they can't close
                slices[0].asSlice(segmentOffset, length),
                length,
                chunkSizePower,
                fileKey,
                messageId,
                frameSize,
                algorithmId,
                directoryKey,
                this.decryptedPages,
                this.inProgressPages,
                sliceAbsoluteOffset  // must pass the absolute file offset
            );
        } else {
            return new MultiSegmentImpl(
                newResourceDescription,
                null, // clones don't have an Arena, as they can't close
                slices,
                segmentOffset,  // this is the offset within the first segment
                length,
                chunkSizePower,
                fileKey,
                messageId,
                frameSize,
                algorithmId,
                directoryKey,
                this.decryptedPages,
                this.inProgressPages,
                sliceAbsoluteOffset  // Pass the absolute file offset
            );
        }
    }

    @Override
    public final void close() throws IOException {
        if (curSegment == null) {
            return;
        }

        // the master IndexInput has an Arena and is able
        // to release all resources (unmap segments) - a
        // side effect is that other threads still using clones
        // will throw IllegalStateException
        if (arena != null) {
            while (arena.scope().isAlive()) {
                try {
                    arena.close();
                    break;
                } catch (@SuppressWarnings("unused") IllegalStateException e) {
                    Thread.onSpinWait();
                }
            }
        }

        // make sure all accesses to this IndexInput instance throw NPE:
        curSegment = null;
        Arrays.fill(segments, null);
    }

    /**
     * Optimization of MemorySegmentIndexInput for when there is only one
     * segment.
     */
    static final class SingleSegmentImpl extends LazyDecryptedMemorySegmentIndexInput {

        SingleSegmentImpl(
            String resourceDescription,
            Arena arena,
            MemorySegment segment,
            long length,
            int chunkSizePower,
            byte[] fileKey,
            byte[] messageId,
            long frameSize,
            short algorithmId,
            byte[] directoryKey,
            AtomicBitSet decryptedPages,
            AtomicBitSet inProgressPages,
            long decryptionBaseOffset
        ) {
            super(
                resourceDescription,
                arena,
                new MemorySegment[] { segment },
                length,
                chunkSizePower,
                fileKey,
                messageId,
                frameSize,
                algorithmId,
                directoryKey,
                decryptedPages,
                inProgressPages,
                decryptionBaseOffset
            );
            this.curSegmentIndex = 0;
        }

        @Override
        public void seek(long pos) throws IOException {
            ensureOpen();
            try {
                curPosition = Objects.checkIndex(pos, resourceLength + 1);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "seek", pos);
            }
        }

        @Override
        public long getFilePointer() {
            ensureOpen();
            return curPosition;
        }

        @Override
        public byte readByte(long pos) throws IOException {
            try {
                // For single segment, pos is the absolute file position
                long addr = curSegment.address() + pos;
                decryptAndProtectFrameBased(
                    resourceDescription,
                    resourceLength,
                    decryptedPages,
                    inProgressPages,
                    addr,
                    1,
                    getDecryptionOffset(pos),
                    fileKey,
                    directoryKey,
                    messageId,
                    frameSize
                );

                return curSegment.get(LAYOUT_BYTE, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            }
        }

        @Override
        public short readShort(long pos) throws IOException {
            try {
                // Decrypt 2 bytes for short
                long addr = curSegment.address() + pos;
                decryptAndProtectFrameBased(
                    resourceDescription,
                    resourceLength,
                    decryptedPages,
                    inProgressPages,
                    addr,
                    2,
                    getDecryptionOffset(pos),
                    fileKey,
                    directoryKey,
                    messageId,
                    frameSize
                );

                return curSegment.get(LAYOUT_LE_SHORT, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            }
        }

        @Override
        public int readInt(long pos) throws IOException {
            try {
                // Decrypt 4 bytes for int
                long addr = curSegment.address() + pos;
                decryptAndProtectFrameBased(
                    resourceDescription,
                    resourceLength,
                    decryptedPages,
                    inProgressPages,
                    addr,
                    4,
                    getDecryptionOffset(pos),
                    fileKey,
                    directoryKey,
                    messageId,
                    frameSize
                );

                return curSegment.get(LAYOUT_LE_INT, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            } catch (IOException e) {
                throw new IOException("Decryption failed", e);
            }
        }

        @Override
        public long readLong(long pos) throws IOException {
            try {
                // Decrypt 8 bytes for long
                long addr = curSegment.address() + pos;
                decryptAndProtectFrameBased(
                    resourceDescription,
                    resourceLength,
                    decryptedPages,
                    inProgressPages,
                    addr,
                    8,
                    getDecryptionOffset(pos),
                    fileKey,
                    directoryKey,
                    messageId,
                    frameSize
                );

                return curSegment.get(LAYOUT_LE_LONG, pos);
            } catch (IndexOutOfBoundsException e) {
                throw handlePositionalIOOBE(e, "read", pos);
            } catch (NullPointerException | IllegalStateException e) {
                throw alreadyClosed(e);
            } catch (IOException e) {
                throw new IOException("Decryption failed", e);
            }
        }
    }

    /**
     * This class adds offset support to MemorySegmentIndexInput, which is
     * needed for slices.
     */
    static final class MultiSegmentImpl extends LazyDecryptedMemorySegmentIndexInput {

        private final long offset;

        MultiSegmentImpl(
            String resourceDescription,
            Arena arena,
            MemorySegment[] segments,
            long offset,
            long length,
            int chunkSizePower,
            byte[] fileKey,
            byte[] messageId,
            long frameSize,
            short algorithmId,
            byte[] directoryKey,
            AtomicBitSet decryptedPages,
            AtomicBitSet inProgressPages,
            long decryptionBaseOffset
        ) {
            super(
                resourceDescription,
                arena,
                segments,
                length,
                chunkSizePower,
                fileKey,
                messageId,
                frameSize,
                algorithmId,
                directoryKey,
                decryptedPages,
                inProgressPages,
                decryptionBaseOffset
            );
            this.offset = offset;
            try {
                seek(0L);
            } catch (IOException ioe) {
                throw new AssertionError(ioe);
            }
            assert curSegment != null && curSegmentIndex >= 0;
        }

        @Override
        RuntimeException handlePositionalIOOBE(RuntimeException unused, String action, long pos) throws IOException {
            return super.handlePositionalIOOBE(unused, action, pos - offset);
        }

        @Override
        public void seek(long pos) throws IOException {
            assert pos >= 0L : "negative position";
            super.seek(pos + offset);
        }

        @Override
        public long getFilePointer() {
            return super.getFilePointer() - offset;
        }

        @Override
        public byte readByte(long pos) throws IOException {
            return super.readByte(pos + offset);
        }

        @Override
        public short readShort(long pos) throws IOException {
            return super.readShort(pos + offset);
        }

        @Override
        public int readInt(long pos) throws IOException {
            return super.readInt(pos + offset);
        }

        @Override
        public long readLong(long pos) throws IOException {
            return super.readLong(pos + offset);
        }

        @Override
        LazyDecryptedMemorySegmentIndexInput buildSlice(String sliceDescription, long ofs, long length) {
            return super.buildSlice(sliceDescription, this.offset + ofs, length);
        }

        @Override
        protected long getDecryptionOffset() {
            // getFilePointer() already returns position relative to this slice
            return decryptionBaseOffset + offset + super.getFilePointer();
        }

        @Override
        protected long getDecryptionOffset(long pos) {
            // pos is relative to the slice, we need to add offset
            return decryptionBaseOffset + offset + pos;
        }
    }
}
