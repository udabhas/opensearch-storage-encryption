/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.directio;

import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.directio.DirectIoConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.LockFactory;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.pool.MemorySegmentPool;
import org.opensearch.index.store.pool.Pool;
import org.opensearch.index.store.read_ahead.ReadaheadContext;
import org.opensearch.index.store.read_ahead.ReadaheadManager;
import org.opensearch.index.store.read_ahead.Worker;
import org.opensearch.index.store.read_ahead.impl.ReadaheadManagerImpl;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;

@SuppressForbidden(reason = "uses custom DirectIO")
public final class CryptoDirectIODirectory extends FSDirectory {
    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectIODirectory.class);
    private final AtomicLong nextTempFileCounter = new AtomicLong();

    private final Pool<MemorySegmentPool.SegmentHandle> memorySegmentPool;
    private final BlockCache<RefCountedMemorySegment> blockCache;
    private final Worker readAheadworker;
    private final KeyResolver keyResolver;
    private final Provider provider;

    private final Map<String, EncryptionFooter> footerCache = new ConcurrentHashMap<>();

    public CryptoDirectIODirectory(
        Path path,
        LockFactory lockFactory,
        Provider provider,
        KeyResolver keyResolver,
        Pool<MemorySegmentPool.SegmentHandle> memorySegmentPool,
        BlockCache<RefCountedMemorySegment> blockCache,
        BlockLoader<MemorySegmentPool.SegmentHandle> blockLoader,
        Worker worker
    )
        throws IOException {
        super(path, lockFactory);
        this.keyResolver = keyResolver;
        this.memorySegmentPool = memorySegmentPool;
        this.blockCache = blockCache;
        this.readAheadworker = worker;
        this.provider = provider;
    }

    @Override
    public IndexInput openInput(String name, IOContext context) throws IOException {
        ensureOpen();
        ensureCanRead(name);

        Path file = getDirectory().resolve(name);
        long rawFileSize = Files.size(file);
        if (rawFileSize == 0) {
            throw new IOException("Cannot open empty file with DirectIO: " + file);
        }

        // Calculate content length with OSEF validation
        long contentLength = calculateContentLengthWithValidation(file, rawFileSize);

        ReadaheadManager readAheadManager = new ReadaheadManagerImpl(readAheadworker);
        ReadaheadContext readAheadContext = readAheadManager.register(file, contentLength);
        BlockSlotTinyCache pinRegistry = new BlockSlotTinyCache(blockCache, file, contentLength);

        LOGGER.info("Calling {} , and its raw size - {} , with content-length = {} , context - {}",
                name, rawFileSize, contentLength, context );

        return CachedMemorySegmentIndexInput
            .newInstance(
                "CachedMemorySegmentIndexInput(path=\"" + file + "\")",
                file,
                contentLength,
                blockCache,
                readAheadManager,
                readAheadContext,
                pinRegistry
            );
    }

    @Override
    public IndexOutput createOutput(String name, IOContext context) throws IOException {
        if (name.contains("segments_") || name.endsWith(".si")) {
            return super.createOutput(name, context);
        }

        ensureOpen();
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        return new BufferIOWithCaching(
                name,
                path,
                fos,
                this.keyResolver.getDataKey().getEncoded(),
                keyResolver.getIvBytes(),
                this.memorySegmentPool,
                this.blockCache,
                this.provider
        );

    }

    @Override
    public IndexOutput createTempOutput(String prefix, String suffix, IOContext context) throws IOException {
        if (prefix.contains("segments_") || prefix.endsWith(".si")) {
            return super.createTempOutput(prefix, suffix, context);
        }

        ensureOpen();
        String name = getTempFileName(prefix, suffix, nextTempFileCounter.getAndIncrement());
        Path path = directory.resolve(name);
        OutputStream fos = Files.newOutputStream(path, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW);

        return new BufferIOWithCaching(
                name,
                path,
                fos,
                this.keyResolver.getDataKey().getEncoded(),
                keyResolver.getIvBytes(),
                this.memorySegmentPool,
                this.blockCache,
                this.provider
        );
    }

    // only close resources owned by this directory type.
    // the actual directory is closed only once (see HybridCryptoDirectory.java)
    @Override
    @SuppressWarnings("ConvertToTryWithResources")
    public synchronized void close() throws IOException {
        footerCache.clear();
        readAheadworker.close();
    }

    private EncryptionFooter getOrReadFooter(String fileName, Path file) {
        EncryptionFooter footer = footerCache.get(fileName);
        if(footer != null) {
            LOGGER.info("Footer cache hit for {}", fileName);
            return footer;
        }

        LOGGER.info("Footer cache miss for {}, reading from file", fileName);
        footer = readFooterFromFile(file);
        if (footer != null) {
            LOGGER.info("Footer read successfully for {}, footerLength={}", fileName, footer.getFooterLength());
            footerCache.put(fileName, footer);
            return footer;
        }
        LOGGER.warn("Failed to read footer for {}", fileName);
        return null;
    }

    private EncryptionFooter readFooterFromFile(Path file) {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            long fileSize = channel.size();
            if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
                return null;
            }

            // Validate magic bytes
            ByteBuffer magicBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MAGIC.length);
            channel.read(magicBuffer, fileSize - EncryptionMetadataTrailer.MAGIC.length);
            magicBuffer.flip();

            if (!isValidOSEFFile(magicBuffer.array())) {
                return null;
            }

            // Read MIN_FOOTER_SIZE to get footer length
            ByteBuffer minBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            channel.read(minBuffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            
            int footerLength = EncryptionFooter.calculateFooterLength(minBuffer.array());
            
            // Read complete footer from correct position
            ByteBuffer footerBuffer = ByteBuffer.allocate(footerLength);
            channel.read(footerBuffer, fileSize - footerLength);
            
            return EncryptionFooter.deserialize(footerBuffer.array(), keyResolver.getDataKey().getEncoded());
        } catch (Exception e) {
            LOGGER.warn("Failed to read footer from file: {}", file, e);
            return null;
        }
    }

    @Override
    public void deleteFile(String name) throws IOException {
        Path file = getDirectory().resolve(name);
        
        footerCache.remove(name);

        if (blockCache != null) {
            try {
                long fileSize = Files.size(file);
                if (fileSize > 0) {
                    final int totalBlocks = (int) ((fileSize + CACHE_BLOCK_SIZE - 1) >>> CACHE_BLOCK_SIZE_POWER);
                    for (int i = 0; i < totalBlocks; i++) {
                        final long blockOffset = (long) i << CACHE_BLOCK_SIZE_POWER;
                        FileBlockCacheKey key = new FileBlockCacheKey(file, blockOffset);
                        blockCache.invalidate(key);
                    }
                }
            } catch (IOException e) {
                LOGGER.warn("Failed to get file size", e);
            }
        }

        super.deleteFile(name);
    }

    /**
     * Calculate content length with OSEF validation
     */
    private long calculateContentLengthWithValidation(Path file, long rawFileSize) throws IOException {
        String fileName = file.getFileName().toString();
        
        if (rawFileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            LOGGER.info("File {} too small ({} bytes), returning raw size", fileName, rawFileSize);
            return rawFileSize;
        }
        
        // Quick magic check first
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            ByteBuffer minBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            channel.read(minBuffer, rawFileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);

            if (!isValidOSEFFile(minBuffer.array())) {
                LOGGER.info("File {} has no valid OSEF magic bytes, returning raw size", fileName);
                return rawFileSize;
            }
        }
        
        LOGGER.info("File {} has valid OSEF magic, reading footer", fileName);
        
        // Get cached footer and return content length
        EncryptionFooter footer = getOrReadFooter(fileName, file);
        if(footer == null) {
            LOGGER.warn("File {} footer is null, returning raw size", fileName);
            return rawFileSize;
        }
        
        long fileLength = rawFileSize - footer.getFooterLength();
        LOGGER.info("File {} calculated length: {} (raw={}, footerLen={})", fileName, fileLength, rawFileSize, footer.getFooterLength());
        
        if (fileLength < 0) {
            LOGGER.error("File {} has negative content length! Returning raw size", fileName);
            return rawFileSize;
        }
        return fileLength;
    }

    /**
     * Check if file has valid OSEF magic bytes
     */
    private boolean isValidOSEFFile(byte[] minFooterBytes) {
        int magicOffset = minFooterBytes.length - EncryptionMetadataTrailer.MAGIC.length;
        for (int i = 0; i < EncryptionMetadataTrailer.MAGIC.length; i++) {
            if (minFooterBytes[magicOffset + i] != EncryptionMetadataTrailer.MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public long fileLength(String name) throws IOException {
        ensureOpen();
        Path file = getDirectory().resolve(name);
        long rawFileSize = Files.size(file);
        return calculateContentLengthWithValidation(file, rawFileSize);
    }
}
