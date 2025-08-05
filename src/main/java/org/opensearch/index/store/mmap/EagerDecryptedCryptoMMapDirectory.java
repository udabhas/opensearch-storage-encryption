/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.mmap;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiPredicate;
import java.util.stream.IntStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.MMapDirectory;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.cipher.OpenSslNativeCipher;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.footer.HkdfKeyDerivation;
import org.opensearch.index.store.iv.KeyIvResolver;

@SuppressWarnings("preview")
@SuppressForbidden(reason = "temporary bypass")
public final class EagerDecryptedCryptoMMapDirectory extends MMapDirectory {
    private static final Logger LOGGER = LogManager.getLogger(EagerDecryptedCryptoMMapDirectory.class);

    private final KeyIvResolver keyIvResolver;
    private final ConcurrentHashMap<String, FileMetadata> fileMetadataCache = new ConcurrentHashMap<>();
    
    private static class FileMetadata {
        final byte[] fileKey;
        final byte[] messageId;
        final long frameSize;
        final int footerLength;
        
        FileMetadata(byte[] fileKey, byte[] messageId, long frameSize, int footerLength) {
            this.fileKey = fileKey;
            this.messageId = messageId;
            this.frameSize = frameSize;
            this.footerLength = footerLength;
        }
    }

    public EagerDecryptedCryptoMMapDirectory(Path path, Provider provider, KeyIvResolver keyIvResolver) throws IOException {
        super(path);
        this.keyIvResolver = keyIvResolver;
    }

    /**
     * Sets the preload predicate based on file extension list.
     *
     * @param preLoadExtensions extensions to preload (e.g., ["dvd", "tim",
     * "*"])
     * @throws IOException if preload configuration fails
     */
    public void setPreloadExtensions(Set<String> preLoadExtensions) throws IOException {
        if (!preLoadExtensions.isEmpty()) {
            this.setPreload(createPreloadPredicate(preLoadExtensions));
        }
    }

    private static BiPredicate<String, IOContext> createPreloadPredicate(Set<String> preLoadExtensions) {
        if (preLoadExtensions.contains("*")) {
            return MMapDirectory.ALL_FILES;
        }
        return (fileName, context) -> {
            int dotIndex = fileName.lastIndexOf('.');
            if (dotIndex > 0) {
                String ext = fileName.substring(dotIndex + 1);
                return preLoadExtensions.contains(ext);
            }
            return false;
        };
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        ensureOpen();
        ensureCanRead(name);

        Path file = getDirectory().resolve(name);
        boolean confined = context == IOContext.READONCE;
        Arena arena = confined ? Arena.ofConfined() : Arena.ofShared();

        // TODO: Make it a constant.
        int chunkSizePower = 34;
        boolean success = false;

        try (var fc = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            final long fileSize = fc.size();
            
            // Try to detect if file has footer, fallback to old format if not
            boolean hasFooter = hasEncryptionFooter(fc);
            
            if (hasFooter) {
                FileMetadata metadata = getOrReadFileMetadata(name, fc);
                final long logicalSize = fileSize - metadata.footerLength;
                MemorySegment[] segments = mmapAndDecrypt(fc, logicalSize, arena, chunkSizePower, name, context, metadata);

                final IndexInput in = MemorySegmentIndexInput
                    .newInstance("CryptoMemorySegmentIndexInput(path=\"" + file + "\")", arena, segments, logicalSize, chunkSizePower);
                success = true;
                return in;
            } else {
                // Fallback to old format - use legacy decryption
                MemorySegment[] segments = mmapAndDecryptLegacy(fc, fileSize, arena, chunkSizePower, name, context);

                final IndexInput in = MemorySegmentIndexInput
                    .newInstance("CryptoMemorySegmentIndexInput(path=\"" + file + "\")", arena, segments, fileSize, chunkSizePower);
                success = true;
                return in;
            }
        } catch (Throwable ex) {
            throw new IOException("Failed to mmap/decrypt " + file, ex);
        } finally {
            if (success == false) {
                arena.close();
            }
        }
    }

    private FileMetadata getOrReadFileMetadata(String name, FileChannel fc) throws IOException {
        return fileMetadataCache.computeIfAbsent(name, k -> {
            try {
                EncryptionFooter footer = readFooterFromFile(fc);
                byte[] directoryKey = keyIvResolver.getDataKey().getEncoded();
                byte[] derivedKey = HkdfKeyDerivation.deriveAesKey(directoryKey, footer.getMessageId(), "file-encryption");
                
                // Calculate footer length
                long fileSize = fc.size();
                ByteBuffer buffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
                fc.read(buffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
                int footerLength = EncryptionFooter.calculateFooterLength(buffer.array());
                
                return new FileMetadata(derivedKey, footer.getMessageId(), footer.getFrameSize(), footerLength);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    private EncryptionFooter readFooterFromFile(FileChannel fc) throws IOException {
        long fileSize = fc.size();
        if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            throw new IOException("File too small to contain encryption footer");
        }
        
        // First read minimum footer to get actual length
        ByteBuffer minBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
        fc.read(minBuffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
        
        int footerLength = EncryptionFooter.calculateFooterLength(minBuffer.array());
        
        // Read complete footer
        ByteBuffer footerBuffer = ByteBuffer.allocate(footerLength);
        int bytesRead = fc.read(footerBuffer, fileSize - footerLength);
        
        if (bytesRead != footerLength) {
            throw new IOException("Failed to read complete footer");
        }
        
        // Use directory key for footer authentication
        return EncryptionFooter.deserialize(footerBuffer.array(), keyIvResolver.getDataKey().getEncoded());
    }

    private MemorySegment[] mmapAndDecrypt(FileChannel fc, long size, Arena arena, int chunkSizePower, String name, IOContext context, FileMetadata metadata)
        throws Throwable {
        final long chunkSize = 1L << chunkSizePower;
        final int numSegments = (int) ((size + chunkSize - 1) >>> chunkSizePower);

        final MemorySegment[] segments = new MemorySegment[numSegments];

        long offset = 0;
        for (int i = 0; i < numSegments; i++) {
            long remaining = size - offset;
            long segmentSize = Math.min(chunkSize, remaining);

            MemorySegment mmapSegment = fc.map(MapMode.PRIVATE, offset, segmentSize, arena);

            if (mmapSegment.address() == 0 || mmapSegment.address() == -1) {
                throw new IOException("mmap failed at offset: " + offset);
            }

            try {
                if (mmapSegment.address() % PanamaNativeAccess.getPageSize() == 0) {
                    PanamaNativeAccess.madvise(mmapSegment.address(), segmentSize, PanamaNativeAccess.MADV_WILLNEED);
                }
            } catch (Throwable t) {
                LOGGER.warn("madvise MADV_WILLNEED failed for file {} with IOcontext {}", name, context, t);
            }

            decryptSegment(arena, mmapSegment, offset, metadata);

            segments[i] = mmapSegment;
            offset += segmentSize;
        }

        return segments;
    }

    private boolean hasEncryptionFooter(FileChannel fc) {
        try {
            long fileSize = fc.size();
            if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
                return false;
            }
            
            // Check for magic bytes at the end
            ByteBuffer magicBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MAGIC.length);
            fc.read(magicBuffer, fileSize - EncryptionMetadataTrailer.MAGIC.length);
            
            return java.util.Arrays.equals(magicBuffer.array(), EncryptionMetadataTrailer.MAGIC);
        } catch (Exception e) {
            return false;
        }
    }
    
    private MemorySegment[] mmapAndDecryptLegacy(FileChannel fc, long size, Arena arena, int chunkSizePower, String name, IOContext context)
        throws Throwable {
        final long chunkSize = 1L << chunkSizePower;
        final int numSegments = (int) ((size + chunkSize - 1) >>> chunkSizePower);

        final MemorySegment[] segments = new MemorySegment[numSegments];
        final byte[] key = keyIvResolver.getDataKey().getEncoded();
        final byte[] iv = keyIvResolver.getIvBytes();

        long offset = 0;
        for (int i = 0; i < numSegments; i++) {
            long remaining = size - offset;
            long segmentSize = Math.min(chunkSize, remaining);

            MemorySegment mmapSegment = fc.map(MapMode.PRIVATE, offset, segmentSize, arena);

            if (mmapSegment.address() == 0 || mmapSegment.address() == -1) {
                throw new IOException("mmap failed at offset: " + offset);
            }

            try {
                if (mmapSegment.address() % PanamaNativeAccess.getPageSize() == 0) {
                    PanamaNativeAccess.madvise(mmapSegment.address(), segmentSize, PanamaNativeAccess.MADV_WILLNEED);
                }
            } catch (Throwable t) {
                LOGGER.warn("madvise MADV_WILLNEED failed for file {} with IOcontext {}", name, context, t);
            }

            // Legacy decryption using old IV calculation
            OpenSslNativeCipher.decryptInPlace(arena, mmapSegment.address(), segmentSize, key, iv, offset);

            segments[i] = mmapSegment;
            offset += segmentSize;
        }

        return segments;
    }

    public void decryptSegment(Arena arena, MemorySegment segment, long segmentOffsetInFile, FileMetadata metadata) throws Throwable {
        final long size = segment.byteSize();
        final byte[] directoryKey = keyIvResolver.getDataKey().getEncoded();

        final int twoMB = 1 << 21; // 2 MiB
        final int fourMB = 1 << 22; // 4 MiB
        final int eightMB = 1 << 23; // 8 MiB
        final int sixteenMB = 1 << 24; // 16 MiB

        // Fast-path: no parallelism for ≤ 4 MiB
        if (size <= (4L << 20)) {
            long start = System.nanoTime();

            int frameNumber = (int)(segmentOffsetInFile / metadata.frameSize);
            long offsetWithinFrame = segmentOffsetInFile % metadata.frameSize;
            byte[] frameIV = AesCipherFactory.computeFrameIV(directoryKey, metadata.messageId, frameNumber, offsetWithinFrame);
            OpenSslNativeCipher.decryptInPlace(arena, segment.address(), size, metadata.fileKey, frameIV, segmentOffsetInFile);

            long end = System.nanoTime();
            long durationMs = (end - start) / 1_000_000;
            LOGGER.debug("Eager decryption of {} MiB at offset {} took {} ms", size / 1048576.0, segmentOffsetInFile, durationMs);
            return;
        }

        // Use Openssl for large block decryption.
        final int chunkSize;
        if (size <= (8L << 20)) {
            chunkSize = twoMB;
        } else if (size <= (32L << 20)) {
            chunkSize = fourMB;
        } else if (size <= (64L << 20)) {
            chunkSize = eightMB;
        } else {
            chunkSize = sixteenMB;
        }

        final int numChunks = (int) ((size + chunkSize - 1) / chunkSize);

        // parallel decryptions.
        IntStream.range(0, numChunks).parallel().forEach(i -> {
            long offset = (long) i * chunkSize;
            long length = Math.min(chunkSize, size - offset);
            long fileOffset = segmentOffsetInFile + offset;
            long addr = segment.address() + offset;

            try {
                int frameNumber = (int)(fileOffset / metadata.frameSize);
                long offsetWithinFrame = fileOffset % metadata.frameSize;
                byte[] frameIV = AesCipherFactory.computeFrameIV(directoryKey, metadata.messageId, frameNumber, offsetWithinFrame);
                OpenSslNativeCipher.decryptInPlace(addr, length, metadata.fileKey, frameIV, fileOffset);
            } catch (Throwable t) {
                throw new RuntimeException("Decryption failed at offset: " + fileOffset, t);
            }
        });
    }
}
