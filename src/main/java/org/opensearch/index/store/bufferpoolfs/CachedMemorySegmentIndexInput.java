/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_MASK;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.AlreadyClosedException;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.RandomAccessInput;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.index.store.read_ahead.ReadaheadContext;
import org.opensearch.index.store.read_ahead.ReadaheadManager;

/**
 * A high-performance IndexInput implementation that uses memory-mapped segments with block-level caching.
 *
 * <p>This implementation provides :
 * <ul>
 * <li>Block-aligned cached memory segments for efficient random access</li>
 * <li>Read-ahead support for sequential access patterns</li>
 * <li>Optimized bulk operations for primitive arrays</li>
 * <li>Slice support with offset management</li>
 * </ul>
 *
 * <p>The class uses a {@link RadixBlockTable} for L1 caching and falls back to
 * the main {@link BlockCache} (Caffeine L2) for cache misses.
 *
 * <p>The L1 cache provides zero-collision, lock-free lookups via two plain array reads.
 * Because the cached value ({@link RefCountedByteBuffer}) is GC-managed and carries no
 * generation counter, L1 coherence is maintained by an L2-eviction callback
 * ({@link RadixBlockTableRegistry#onEviction}) that clears the stale L1 pointer.
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
public class CachedMemorySegmentIndexInput extends IndexInput implements RandomAccessInput {

    private static final Logger LOGGER = LogManager.getLogger(CachedMemorySegmentIndexInput.class);

    // ---- fdc-debug: closer inventory for close() (throwaway instrumentation, Track 17) ----
    // Mirror of HybridCryptoDirectory.fdcCallerChain (deliberately duplicated rather than shared:
    // this is throwaway debug code and not worth a cross-package utility). Bounded for the same
    // reason as the open side - close() is a shard-LIFECYCLE / traversal-teardown event, not a
    // per-block read. Full chain once per distinct closer; every other line carries only the hash.
    private static final int FDC_MAX_FRAMES = 20;
    private static final Set<Integer> FDC_SEEN_CLOSESITES = ConcurrentHashMap.newKeySet();

    /** OpenSearch/Lucene frames only, capped. Lazy: frames past the cap are never materialised. */
    private static String fdcCallerChain(int maxFrames) {
        StringBuilder sb = new StringBuilder(256);
        StackWalker.getInstance().walk(frames -> {
            frames
                .filter(f -> f.getClassName().startsWith("org.opensearch") || f.getClassName().startsWith("org.apache.lucene"))
                .limit(maxFrames)
                .forEach(
                    f -> sb
                        .append(f.getClassName())
                        .append('.')
                        .append(f.getMethodName())
                        .append(':')
                        .append(f.getLineNumber())
                        .append(" <- ")
                );
            return null;
        });
        return sb.toString();
    }

    static final ValueLayout.OfByte LAYOUT_BYTE = ValueLayout.JAVA_BYTE;
    static final ValueLayout.OfShort LAYOUT_LE_SHORT = ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfInt LAYOUT_LE_INT = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfLong LAYOUT_LE_LONG = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    static final ValueLayout.OfFloat LAYOUT_LE_FLOAT = ValueLayout.JAVA_FLOAT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    final long length;

    final Path path;
    final BlockCache<RefCountedByteBuffer> blockCache;
    final ReadaheadManager readaheadManager;
    final ReadaheadContext readaheadContext;

    final long absoluteBaseOffset; // absolute position in original file where this input starts
    final boolean isSlice; // true for slices, false for main instances

    /**
     * When true, this input never consults or populates L1 (RadixBlockTable) or L2 (Caffeine): every
     * block is read from disk via DirectIO, decrypted, and handed straight back to the reader.
     *
     * <p>For one-shot bulk readers whose blocks are never re-read, caching is pure loss — it evicts
     * blocks that search still needs in order to store blocks nobody will ask for again.
     *
     * <p>Inherited by every {@code clone()} and {@code slice()} via {@link #buildSlice}, so the
     * decision is made once per opened input and follows all derived inputs. This is deliberately a
     * per-instance field rather than a thread-local: each derived input owns its own retained block
     * ({@code currentBlock}/{@code currentSegment}), so a per-instance decision cannot let one input's
     * buffer be recycled underneath another input reading on the same thread.
     */
    private final boolean skipCache;
    /**
     * fdc-debug: file extension, computed once per input so the per-block tier counters can be broken
     * down by file type without doing string work on the hot path. Answers "which Lucene structures does
     * this flow actually read" - e.g. whether a field data build reads postings (.doc/.tim) or doc values
     * (.dvd/.dvm), which are different mechanisms with different fixes.
     */
    private final String fdcExt;

    long curPosition = 0L; // absolute position within this input (0-based)
    volatile boolean isOpen = true;

    // Single block cache for current access
    private long currentBlockOffset = -1;
    private BlockCacheValue<RefCountedByteBuffer> currentBlock = null;

    // Cached offset from last getCacheBlockWithOffset call (avoid BlockAccess allocation)
    private int lastOffsetInBlock;

    // --- JIT-friendly fast-path fields ---
    // Pre-computed boundary: the position (relative to this input) where the current block ends.
    private long currentBlockEnd = 0L;
    // Cached MemorySegment for direct access without getCacheBlockWithOffset
    private MemorySegment currentSegment;
    // Block-aligned file offset of the current block (used to compute offset within segment)
    private long currentBlockStart;
    private long currentBlockStartRelative; // = currentBlockStart - absoluteBaseOffset (input-relative)

    private final RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixBlockTable;
    private final RadixBlockTableRegistry radixBlockTableRegistry; // shared by master and slices; only master calls release()

    // Safe because IndexInput instances are not thread-safe per Lucene contract -
    // each thread must use its own clone().
    private boolean lastAccessWasCacheHit;

    /**
     * Creates a new CachedMemorySegmentIndexInput instance.
     *
     * @param resourceDescription description of the resource for debugging
     * @param path the file path being accessed
     * @param length the length of the file in bytes
     * @param blockCache the main block cache for storing memory segments
     * @param readaheadManager manager for read-ahead operations
     * @param readaheadContext context for read-ahead policy decisions
     * @param radixBlockTable L1 cache for recently accessed blocks
     * @param radixBlockTableRegistry registry for lifecycle management (release on close)
     * @param skipCache when true, bypass L1/L2 entirely and read+decrypt every block from disk
     * @return a new CachedMemorySegmentIndexInput instance
     */
    public static CachedMemorySegmentIndexInput newInstance(
        String resourceDescription,
        Path path,
        long length,
        BlockCache<RefCountedByteBuffer> blockCache,
        ReadaheadManager readaheadManager,
        ReadaheadContext readaheadContext,
        RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixBlockTable,
        RadixBlockTableRegistry radixBlockTableRegistry,
        boolean skipCache
    ) {
        CachedMemorySegmentIndexInput input = new CachedMemorySegmentIndexInput(
            resourceDescription,
            path,
            0,
            length,
            blockCache,
            readaheadManager,
            readaheadContext,
            false,
            radixBlockTable,
            radixBlockTableRegistry,
            skipCache
        );
        try {
            input.seek(0L);
        } catch (IOException ioe) {
            throw new AssertionError(ioe);
        }
        return input;
    }

    private CachedMemorySegmentIndexInput(
        String resourceDescription,
        Path path,
        long absoluteBaseOffset,
        long length,
        BlockCache<RefCountedByteBuffer> blockCache,
        ReadaheadManager readaheadManager,
        ReadaheadContext readaheadContext,
        boolean isSlice,
        RadixBlockTable<BlockCacheValue<RefCountedByteBuffer>> radixBlockTable,
        RadixBlockTableRegistry radixBlockTableRegistry,
        boolean skipCache
    ) {
        super(resourceDescription);
        // Slices inherit their parent's already-normalized path. Non-slice (master)
        // instances still normalize once in case the caller passes an unnormalized path.
        if (isSlice && StaticConfigs.memorySegmentGlobalArenaAndNormalizePathOptimEnabled()) {
            this.path = path;
        } else {
            this.path = path.toAbsolutePath().normalize();
        }
        this.absoluteBaseOffset = absoluteBaseOffset;
        this.length = length;
        this.blockCache = blockCache;
        this.readaheadManager = readaheadManager;
        this.readaheadContext = readaheadContext;
        this.isSlice = isSlice;
        this.radixBlockTable = radixBlockTable;
        this.radixBlockTableRegistry = radixBlockTableRegistry;
        this.skipCache = skipCache;
        this.fdcExt = fdcExtensionOf(path);
        // fdc-debug: the skipCache decision itself, at the moment it is fixed for this instance.
        // isSlice distinguishes the master input (openInput) from every clone()/slice() derived from it.
        if (FdcDebug.on(LOGGER)) {
            FdcDebug.count(isSlice ? "input.create.slice" : "input.create.master");
            FdcDebug
                .log(
                    LOGGER,
                    "fdc-debug input.create isSlice={} skipCache={} id={} path={} base={} len={} thread={}",
                    isSlice,
                    skipCache,
                    System.identityHashCode(this),
                    path,
                    absoluteBaseOffset,
                    length,
                    FdcDebug.thread()
                );
        }
    }

    void ensureOpen() {
        if (!isOpen) {
            throw alreadyClosed(null);
        }
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

    /**
     * Fail-fast bounds guard for the COLD read paths (sequential slow helpers, {@code readBytes}, the
     * array reads, {@code readGroupVInt}, and the positional multi-byte reads). Throws {@link EOFException}
     * (via {@link #handlePositionalIOOBE}) if a read of {@code n} bytes at input-relative {@code pos} would
     * extend past the logical (footer-excluded) {@code length}, or {@link IllegalArgumentException} if
     * {@code pos} is negative.
     *
     * <p>This is the safety net behind the length-capped {@code currentBlockEnd}: pooled block buffers are
     * always the fixed 8KB segment size even for the final partial block (whose tail is zero-fill / footer
     * ciphertext), so a bound based on {@code seg.byteSize()} alone would let an over-read return fabricated
     * bytes. Under the unauthenticated AES-CTR read path that would surface only later as a Lucene CRC /
     * {@code CorruptIndexException}; failing fast here turns silent corruption into a clean EOF.
     *
     * <p>Written as {@code n > length - pos} (rather than {@code pos + n > length}) so it cannot overflow
     * for a caller-supplied positional {@code pos}.
     */
    private void ensureInBounds(long pos, long n) throws IOException {
        if (pos < 0 || n > length - pos) {
            throw handlePositionalIOOBE(null, "read", pos);
        }
    }

    /**
    * Optimized method to get both cache block and offset in one operation.
    * Fast path kept small for JIT inlining.
    *
    * @param pos position relative to this input
    * @return MemorySegment for the cache block (offset available in lastOffsetInBlock)
    * @throws IOException if the block cannot be acquired
    */
    private MemorySegment getCacheBlockWithOffset(long pos) throws IOException {
        final long fileOffset = absoluteBaseOffset + pos;
        final long blockOffset = fileOffset & ~CACHE_BLOCK_MASK;
        lastOffsetInBlock = (int) (fileOffset - blockOffset);

        // Fast path: reuse current block if still valid.
        if (blockOffset == currentBlockOffset && currentBlock != null) {
            return currentSegment;
        }
        return acquireCacheBlockOnMiss(blockOffset);
    }

    /**
     * Slow path for cache block acquisition — separated to keep the fast path
     * small enough for JIT inlining.
     */
    private MemorySegment acquireCacheBlockOnMiss(long blockOffset) throws IOException {
        lastAccessWasCacheHit = false;

        final BlockCacheValue<RefCountedByteBuffer> cacheValue = acquireBlock(blockOffset);

        currentBlockOffset = blockOffset;
        currentBlock = cacheValue;

        // Update JIT fast-path fields
        final MemorySegment seg = cacheValue.value().segment();
        currentSegment = seg;
        currentBlockStart = blockOffset;
        currentBlockStartRelative = blockOffset - absoluteBaseOffset;
        // Cap the fast-path boundary at the logical (footer-excluded) length. Pooled block buffers are
        // ALWAYS the fixed segmentSize (8KB) even for the final partial block, whose tail is zero-fill
        // (or footer ciphertext); seg.byteSize() therefore overshoots the file's logical end. Clamping
        // here makes every fast-path check (pos < currentBlockEnd / pos + N <= currentBlockEnd) also
        // enforce EOF with no extra hot-path branch, so an over-read past EOF misses the fast path and
        // is routed to the slow helpers where it throws EOFException instead of returning fabricated
        // zero bytes — critical because the read path is unauthenticated AES-CTR (fabricated bytes would
        // surface only later as a Lucene CRC / CorruptIndexException).
        currentBlockEnd = Math.min(currentBlockStartRelative + seg.byteSize(), length);

        // Notify readahead manager of access pattern.
        // Skipped for cache-bypass readers: readaheadContext is SHARED by reference with every clone
        // and slice of this file (see buildSlice), so feeding it bypass accesses would both prefetch
        // blocks into a cache this reader never consults and skew the sequential-access signal that
        // drives prefetch for the search readers on the same file.
        if (readaheadContext != null && !skipCache) {
            readaheadContext.onAccess(blockOffset, lastAccessWasCacheHit);
        }

        return seg;
    }

    /**
     * Acquires a block for the given block offset, checking L1 (RadixBlockTable)
     * first, then falling back to L2 (Caffeine), then loading from disk.
     *
     * <p>L1 lookup is two plain array reads with no synchronization. On L1 miss,
     * falls through to L2 and publishes back to L1.
     *
     * @param blockOffset the block-aligned file offset
     * @return a BlockCacheValue for the block
     * @throws IOException if the block cannot be acquired after max attempts
     */
    /**
     * Attributes a block acquisition to its caller and tier.
     *
     * <p>Without this the tier counters answer "how many" but not "who", so an L1 hit could not be traced
     * back to the consumer that caused it - the gap that made it impossible to say which of a field data
     * build and a query-phase precompute produced a given hit, even though both were known to be running.
     *
     * <p>This is the hottest site in the plugin - once per block per read - so the caller chain is walked
     * only under {@code -Dopensearch.store.fdcdebug.hotstacks=true}, and then once per distinct call path.
     * The identity hash ties the line back to the {@code input.create} / {@code input.clone} /
     * {@code input.slice} line that produced this input.
     */
    private void traceTier(String tier, long blockOffset) {
        if (FdcDebug.on(LOGGER) == false) {
            return;
        }
        int callsite = FdcDebug.hotSite(LOGGER, "block.acquire." + tier, path);
        FdcDebug
            .log(
                LOGGER,
                "fdc-debug block.acquire tier={} blockOffset={} id={} ext={} skipCache={} path={} thread={} callsite={}",
                tier,
                blockOffset,
                System.identityHashCode(this),
                fdcExt,
                skipCache,
                path,
                FdcDebug.thread(),
                callsite
            );
    }

    /** Extension of a path, or "none". Called once per input, never per block. */
    private static String fdcExtensionOf(java.nio.file.Path p) {
        String name = p.getFileName() == null ? "" : p.getFileName().toString();
        int dot = name.lastIndexOf('.');
        return dot < 0 || dot == name.length() - 1 ? "none" : name.substring(dot + 1);
    }

    private BlockCacheValue<RefCountedByteBuffer> acquireBlock(long blockOffset) throws IOException {
        // Cache-bypass reader: read+decrypt this block from disk and hand it straight back. No L1
        // lookup, no L2 lookup, no publish to either — so this read can neither be served by nor
        // evict anything search has cached. The value is reclaimed by GC once the reader drops it
        // (see BlockCache#loadUncached).
        if (skipCache) {
            if (FdcDebug.on(LOGGER)) {
                FdcDebug.count("input.acquireBlock.BYPASS");
                int callsite = FdcDebug.hotSite(LOGGER, "input.acquireBlock.BYPASS", path);
                FdcDebug
                    .log(
                        LOGGER,
                        "fdc-debug block.acquire route=BYPASS-directio blockOffset={} id={} path={} thread={} callsite={}",
                        blockOffset,
                        System.identityHashCode(this),
                        path,
                        FdcDebug.thread(),
                        callsite
                    );
            }
            final BlockCacheValue<RefCountedByteBuffer> uncached = blockCache.loadUncached(new FileBlockCacheKey(path, blockOffset));
            if (uncached == null) {
                throw new IOException("Unable to acquire uncached block for offset " + blockOffset);
            }
            lastAccessWasCacheHit = false;
            return uncached;
        }

        final long blockId = blockOffset >>> CACHE_BLOCK_SIZE_POWER;
        // Query-profiler handle (null unless a ?profile=true query is scoring on this thread).
        final org.opensearch.index.store.profile.CryptoQueryProfile prof = org.opensearch.index.store.profile.CryptoQueryProfile.current();
        // Is a profile breakdown actually exposed on this thread at read time? Distinguishes "the profiler
        // recorded nothing because nothing happened" from "nothing was recorded because there was no handle
        // to record into" - two states that look identical in a profile response full of zeros.
        if (FdcDebug.on(LOGGER)) {
            FdcDebug.count(prof == null ? "prof.handle.NULL" : "prof.handle.present");
        }

        // ---- L1 lookup: two plain array reads, no fences, no CAS ----
        final org.opensearch.index.store.profile.CryptoNanosMetric l1Timer = (prof != null) ? prof.l1LookupTimer() : null;
        final long l1StartNs = (l1Timer != null) ? l1Timer.start() : 0L;
        BlockCacheValue<RefCountedByteBuffer> entry = radixBlockTable.get(blockId);
        if (l1Timer != null)
            l1Timer.stop(l1StartNs);
        if (entry != null) {
            // fdc-debug: an L1 hit never reaches CaffeineBlockCache at all, so the cache-layer populate
            // counters cannot see it. Counting the tier here is what makes "was this read served BY the
            // pool or did it populate the pool" separable - two different claims with two different costs.
            if (FdcDebug.on(LOGGER)) {
                // Gated AND the per-extension key built inside the gate: this is once per block per read,
                // so an ungated string concatenation here would allocate on the query hot path in
                // production, where tracing is off and the result is discarded.
                FdcDebug.count("block.acquire.L1_HIT");
                FdcDebug.count("block.acquire.L1_HIT." + fdcExt);
                traceTier("L1_HIT", blockOffset);
            }
            lastAccessWasCacheHit = true;
            if (prof != null)
                prof.incL1Hits();
            if (radixBlockTableRegistry != null)
                radixBlockTableRegistry.recordHit();
            // Damp signal: every 4096th L1 hit, touch L2 so Caffeine sees access frequency.
            // This is also an L2 lookup, so time it into the same crypto_l2_lookup_time metric.
            if ((++radixBlockTable.accessCounter & RadixBlockTable.SAMPLE_MASK) == 0) {
                final org.opensearch.index.store.profile.CryptoNanosMetric dampL2Timer = (prof != null) ? prof.l2LookupTimer() : null;
                final long dampL2StartNs = (dampL2Timer != null) ? dampL2Timer.start() : 0L;
                try {
                    blockCache.get(new FileBlockCacheKey(path, blockOffset));
                } finally {
                    if (dampL2Timer != null)
                        dampL2Timer.stop(dampL2StartNs);
                }
            }
            return entry;
        }
        if (prof != null)
            prof.incL1Misses();
        if (radixBlockTableRegistry != null)
            radixBlockTableRegistry.recordMiss();
        // ---- L2 lookup + disk load ----
        final FileBlockCacheKey key = new FileBlockCacheKey(path, blockOffset);
        // Try L2 hit
        final org.opensearch.index.store.profile.CryptoNanosMetric l2Timer = (prof != null) ? prof.l2LookupTimer() : null;
        final long l2StartNs = (l2Timer != null) ? l2Timer.start() : 0L;
        BlockCacheValue<RefCountedByteBuffer> v = blockCache.get(key);
        if (l2Timer != null)
            l2Timer.stop(l2StartNs);
        if (v != null) {
            if (FdcDebug.on(LOGGER)) {
                FdcDebug.count("block.acquire.L2_HIT");
                FdcDebug.count("block.acquire.L2_HIT." + fdcExt);
                traceTier("L2_HIT", blockOffset);
            }
            FdcDebug.count("block.acquire.L2_HIT." + fdcExt);
            if (prof != null)
                prof.incL2Hits();
            // Never insert a transient (degraded-mode, non-pooled, non-cacheable) buffer into the L1
            // RadixBlockTable: it is not accounted in the pool's buffersInUse, and an L1 reference would
            // pin its direct memory indefinitely (the Cleaner can't free it while L1 holds it), re-creating
            // the untracked-direct-memory growth this fix eliminates. Hand it straight back to the reader.
            if (!v.isTransient()) {
                publishToL1(key, blockId, v);
            }
            lastAccessWasCacheHit = true;
            return v;
        }
        // L2 miss — load from disk (deduped by Caffeine)
        if (FdcDebug.on(LOGGER)) {
            FdcDebug.count("block.acquire.MISS_LOADS_AND_POPULATES");
            FdcDebug.count("block.acquire.MISS_LOADS_AND_POPULATES." + fdcExt);
            traceTier("MISS_LOADS_AND_POPULATES", blockOffset);
        }
        FdcDebug.count("block.acquire.MISS_LOADS_AND_POPULATES." + fdcExt);
        if (prof != null)
            prof.incL2Misses();
        BlockCacheValue<RefCountedByteBuffer> loaded = blockCache.getOrLoad(key);
        if (loaded != null) {
            if (!loaded.isTransient()) {
                publishToL1(key, blockId, loaded);
            }
            lastAccessWasCacheHit = false;
            return loaded;
        }
        throw new IOException("Unable to acquire block for offset " + blockOffset);
    }

    /**
     * Publish a block into the L1 {@link RadixBlockTable}, closing the publish-after-evict window.
     *
     * <p>{@link RefCountedByteBuffer} carries no generation token ({@code getGeneration()} returns 0), so L1
     * coherence relies entirely on the L2 removal listener firing {@code onEviction -> table.remove} AFTER the L1
     * entry exists. If an invalidation (a concurrent {@code deleteFile}/{@code rename} of this path) removes the L2
     * key in the window between the caller's {@code blockCache.get(key)} and this {@code put}, the eviction
     * listener's {@code remove} runs as a no-op (the L1 slot is still empty) and we would otherwise install a STALE
     * L1 entry with no surviving L2 entry to ever clear it. A later L1 hit on a delete-then-recreate at the same
     * path (snapshot restore, recovery) would then serve the old inode's bytes under the new key — silent under
     * unauthenticated AES-CTR. It also leaks pool capacity: the orphaned L1 reference pins direct memory the Cleaner
     * cannot free.
     *
     * <p>Fix: install the L1 entry, then re-check that L2 still holds the key; if it does not, the key was
     * invalidated concurrently — drop the just-published L1 entry so no stale pointer survives.
     */
    private void publishToL1(FileBlockCacheKey key, long blockId, BlockCacheValue<RefCountedByteBuffer> value) {
        radixBlockTable.put(blockId, value);
        if (blockCache.get(key) == null) {
            // L2 entry was invalidated between the caller's get/load and this put; remove the stale L1 entry.
            radixBlockTable.remove(blockId);
        }
    }

    /**
     * Slow path for sequential reads — called only at block boundaries (~1 in CACHE_BLOCK_SIZE calls).
     * Kept as a separate method so the JIT can keep readByte/readShort/readInt/readLong tiny.
     */
    private byte readByteSlow(long pos) throws IOException {
        ensureInBounds(pos, Byte.BYTES);
        try {
            final MemorySegment seg = getCacheBlockWithOffset(pos);
            final byte v = seg.get(LAYOUT_BYTE, lastOffsetInBlock);
            curPosition = pos + 1;
            return v;
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    private short readShortSlow(long pos) throws IOException {
        ensureInBounds(pos, Short.BYTES);
        try {
            final MemorySegment seg = getCacheBlockWithOffset(pos);
            final int off = lastOffsetInBlock;
            if (off + Short.BYTES > seg.byteSize()) {
                return super.readShort();
            }
            final short v = seg.get(LAYOUT_LE_SHORT, off);
            curPosition = pos + Short.BYTES;
            return v;
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    private int readIntSlow(long pos) throws IOException {
        ensureInBounds(pos, Integer.BYTES);
        try {
            final MemorySegment seg = getCacheBlockWithOffset(pos);
            final int off = lastOffsetInBlock;
            if (off + Integer.BYTES > seg.byteSize()) {
                return super.readInt();
            }
            final int v = seg.get(LAYOUT_LE_INT, off);
            curPosition = pos + Integer.BYTES;
            return v;
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    private long readLongSlow(long pos) throws IOException {
        ensureInBounds(pos, Long.BYTES);
        try {
            final MemorySegment seg = getCacheBlockWithOffset(pos);
            final int off = lastOffsetInBlock;
            if (off + Long.BYTES > seg.byteSize()) {
                return super.readLong();
            }
            final long v = seg.get(LAYOUT_LE_LONG, off);
            curPosition = pos + Long.BYTES;
            return v;
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final byte readByte() throws IOException {
        final long pos = curPosition;
        if (pos >= currentBlockStartRelative && pos < currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            final byte v = currentSegment.get(LAYOUT_BYTE, off);
            curPosition = pos + 1;
            return v;
        }
        return readByteSlow(pos);
    }

    @Override
    public final void readBytes(byte[] b, int offset, int len) throws IOException {
        if (len == 0)
            return;

        final long startPos = curPosition; // avoid virtual call
        // Guard the full span against the logical length up front: the final pooled block is a fixed 8KB
        // buffer with a zero-fill / footer-ciphertext tail, so the per-block `avail = seg.byteSize()-off`
        // bound below would otherwise silently copy fabricated bytes past EOF (unauthenticated AES-CTR).
        ensureInBounds(startPos, len);
        int remaining = len;
        int bufferOffset = offset;
        long currentPos = startPos;

        try {
            while (remaining > 0) {
                final MemorySegment seg = getCacheBlockWithOffset(currentPos);
                final int offInBlock = lastOffsetInBlock;
                final int avail = (int) (seg.byteSize() - offInBlock);

                // Fast path: full block copy
                if (offInBlock == 0 && remaining >= CACHE_BLOCK_SIZE && seg.byteSize() >= CACHE_BLOCK_SIZE) {
                    MemorySegment.copy(seg, LAYOUT_BYTE, 0L, b, bufferOffset, CACHE_BLOCK_SIZE);
                    remaining -= CACHE_BLOCK_SIZE;
                    bufferOffset += CACHE_BLOCK_SIZE;
                    currentPos += CACHE_BLOCK_SIZE;
                    continue;
                }

                // Partial block
                final int toRead = Math.min(remaining, avail);
                MemorySegment.copy(seg, LAYOUT_BYTE, offInBlock, b, bufferOffset, toRead);

                remaining -= toRead;
                bufferOffset += toRead;
                currentPos += toRead;
            }

            curPosition = startPos + len;

        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", startPos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public void readInts(int[] dst, int offset, int length) throws IOException {
        if (length == 0)
            return;

        final long startPos = getFilePointer();
        final long totalBytes = Integer.BYTES * (long) length;
        ensureInBounds(startPos, totalBytes);

        try {
            final MemorySegment segment = getCacheBlockWithOffset(startPos);
            final int offsetInBlock = lastOffsetInBlock;

            if (offsetInBlock + totalBytes <= segment.byteSize()) {
                MemorySegment.copy(segment, LAYOUT_LE_INT, offsetInBlock, dst, offset, length);
                curPosition += totalBytes;
            } else {
                super.readInts(dst, offset, length);
            }
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", startPos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public void readLongs(long[] dst, int offset, int length) throws IOException {
        if (length == 0)
            return;

        final long startPos = getFilePointer();
        final long totalBytes = Long.BYTES * (long) length;
        ensureInBounds(startPos, totalBytes);

        try {
            final MemorySegment segment = getCacheBlockWithOffset(startPos);
            final int offsetInBlock = lastOffsetInBlock;

            // Check if entire read fits in current cache block
            if (offsetInBlock + totalBytes <= segment.byteSize()) {
                // Fast path: entire read fits in one cache block
                MemorySegment.copy(segment, LAYOUT_LE_LONG, offsetInBlock, dst, offset, length);
                curPosition += totalBytes;
            } else {
                // Slow path: spans cache blocks, fall back to super implementation
                super.readLongs(dst, offset, length);
            }
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", startPos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public void readFloats(float[] dst, int offset, int length) throws IOException {
        if (length == 0)
            return;

        final long startPos = getFilePointer();
        final long totalBytes = Float.BYTES * (long) length;
        ensureInBounds(startPos, totalBytes);

        try {
            final MemorySegment segment = getCacheBlockWithOffset(startPos);
            final int offsetInBlock = lastOffsetInBlock;

            // Check if entire read fits in current cache block
            if (offsetInBlock + totalBytes <= segment.byteSize()) {
                // Fast path: entire read fits in one cache block
                MemorySegment.copy(segment, LAYOUT_LE_FLOAT, offsetInBlock, dst, offset, length);
                curPosition += totalBytes;
            } else {
                super.readFloats(dst, offset, length);
            }
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", startPos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final short readShort() throws IOException {
        final long pos = curPosition;
        if (pos >= currentBlockStartRelative && pos + Short.BYTES <= currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            final short v = currentSegment.get(LAYOUT_LE_SHORT, off);
            curPosition = pos + Short.BYTES;
            return v;
        }
        return readShortSlow(pos);
    }

    @Override
    public final int readInt() throws IOException {
        final long pos = curPosition;
        if (pos >= currentBlockStartRelative && pos + Integer.BYTES <= currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            final int v = currentSegment.get(LAYOUT_LE_INT, off);
            curPosition = pos + Integer.BYTES;
            return v;
        }
        return readIntSlow(pos);
    }

    @Override
    public final long readLong() throws IOException {
        final long pos = curPosition;
        if (pos >= currentBlockStartRelative && pos + Long.BYTES <= currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            final long v = currentSegment.get(LAYOUT_LE_LONG, off);
            curPosition = pos + Long.BYTES;
            return v;
        }
        return readLongSlow(pos);
    }

    @Override
    public void readGroupVInt(int[] dst, int offset) throws IOException {
        // Lucene 10.5.0 removed the segment/reader fast-path overload
        // GroupVIntUtil.readGroupVInt(DataInput, long, IntReader, long, int[], int) — it now
        // unconditionally throws UnsupportedOperationException ("No longer implemented."). The
        // optimization moved into Lucene's baseline decoder, which detects RandomAccessInput and reads
        // group-varint values through this input's positional readInt(long). Delegate to that default;
        // the bytes it reads are already-decrypted plaintext from the cached block (decryption happens
        // once at block-load time in CryptoDirectIOBlockLoader, not per read).
        super.readGroupVInt(dst, offset);
    }

    @Override
    public final int readVInt() throws IOException {
        // this can make JVM less confused (see LUCENE-10366)
        return super.readVInt();
    }

    @Override
    public final long readVLong() throws IOException {
        // this can make JVM less confused (see LUCENE-10366)
        return super.readVLong();
    }

    @Override
    public long getFilePointer() {
        ensureOpen();
        return curPosition;
    }

    /**
     * Returns the absolute file offset for the current position.
     * This is useful for cache keys, encryption, and other operations that need
     * the actual position in the original file.
     *
     * @return the absolute byte offset in the original file
     */
    public long getAbsoluteFileOffset() {
        return absoluteBaseOffset + getFilePointer();
    }

    /**
     * Returns the absolute file offset for a given position within this input.
     * This is useful for cache keys, encryption, and other operations that need
     * the actual position in the original file for random access operations.
     *
     * @param pos position relative to this input (0-based)
     * @return absolute position in the original file
     */
    public long getAbsoluteFileOffset(long pos) {
        return absoluteBaseOffset + pos;
    }

    @Override
    public void seek(long pos) throws IOException {
        ensureOpen();
        if (pos < 0 || pos > length) {
            throw handlePositionalIOOBE(null, "seek", pos);
        }
        this.curPosition = pos;
    }

    @Override
    public byte readByte(long pos) throws IOException {
        if (pos < 0 || pos >= length) {
            return 0;
        }
        if (pos >= currentBlockStartRelative && pos < currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            return currentSegment.get(LAYOUT_BYTE, off);
        }
        try {
            final MemorySegment segment = getCacheBlockWithOffset(pos);
            return segment.get(LAYOUT_BYTE, lastOffsetInBlock);
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public short readShort(long pos) throws IOException {
        if (pos >= currentBlockStartRelative && pos + Short.BYTES <= currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            return currentSegment.get(LAYOUT_LE_SHORT, off);
        }
        // Slow path reads straight from the fixed-size pooled segment, so guard against the logical
        // length before touching it (the final block's tail past EOF is zero-fill / footer ciphertext).
        ensureInBounds(pos, Short.BYTES);
        try {
            final MemorySegment segment = getCacheBlockWithOffset(pos);
            final int offsetInBlock = lastOffsetInBlock;
            if (offsetInBlock + Short.BYTES > segment.byteSize()) {
                long savedPos = getFilePointer();
                try {
                    seek(pos);
                    return readShort();
                } finally {
                    seek(savedPos);
                }
            }
            return segment.get(LAYOUT_LE_SHORT, offsetInBlock);
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public int readInt(long pos) throws IOException {
        if (pos >= currentBlockStartRelative && pos + Integer.BYTES <= currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            return currentSegment.get(LAYOUT_LE_INT, off);
        }
        // Slow path reads straight from the fixed-size pooled segment, so guard against the logical
        // length before touching it (the final block's tail past EOF is zero-fill / footer ciphertext).
        ensureInBounds(pos, Integer.BYTES);
        try {
            final MemorySegment segment = getCacheBlockWithOffset(pos);
            final int offsetInBlock = lastOffsetInBlock;
            if (offsetInBlock + Integer.BYTES > segment.byteSize()) {
                long savedPos = getFilePointer();
                try {
                    seek(pos);
                    return readInt();
                } finally {
                    seek(savedPos);
                }
            }
            return segment.get(LAYOUT_LE_INT, offsetInBlock);
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public long readLong(long pos) throws IOException {
        if (pos >= currentBlockStartRelative && pos + Long.BYTES <= currentBlockEnd) {
            final long off = absoluteBaseOffset + pos - currentBlockStart;
            return currentSegment.get(LAYOUT_LE_LONG, off);
        }
        // Slow path reads straight from the fixed-size pooled segment, so guard against the logical
        // length before touching it (the final block's tail past EOF is zero-fill / footer ciphertext).
        ensureInBounds(pos, Long.BYTES);
        try {
            final MemorySegment segment = getCacheBlockWithOffset(pos);
            final int offsetInBlock = lastOffsetInBlock;
            if (offsetInBlock + Long.BYTES > segment.byteSize()) {
                long savedPos = getFilePointer();
                try {
                    seek(pos);
                    return readLong();
                } finally {
                    seek(savedPos);
                }
            }
            return segment.get(LAYOUT_LE_LONG, offsetInBlock);
        } catch (IndexOutOfBoundsException ioobe) {
            throw handlePositionalIOOBE(ioobe, "read", pos);
        } catch (NullPointerException | IllegalStateException e) {
            throw alreadyClosed(e);
        }
    }

    @Override
    public final long length() {
        return length;
    }

    @Override
    public final CachedMemorySegmentIndexInput clone() {
        // fdc-debug: clone() is THE candidate seam for a per-consumer skip decision. It is
        // also the query hot path (a clone per TermsEnum, a clone per DocsEnum), so the caller chain is
        // walked only under -Dopensearch.store.fdcdebug.hotstacks=true and then only once per distinct
        // call path. Never enable hot stacks while timing anything.
        if (FdcDebug.on(LOGGER)) {
            FdcDebug.count("input.clone");
            int callsite = FdcDebug.hotSite(LOGGER, "input.clone", path);
            FdcDebug
                .log(
                    LOGGER,
                    "fdc-debug input.clone from={} fromIsSlice={} skipCache={} path={} thread={} callsite={}{}",
                    System.identityHashCode(this),
                    isSlice,
                    skipCache,
                    path,
                    FdcDebug.thread(),
                    callsite,
                    FdcDebug.poolState()
                );
        }
        final CachedMemorySegmentIndexInput clone = buildSlice((String) null, 0L, this.length);
        try {
            clone.seek(getFilePointer());
        } catch (IOException ioe) {
            throw new AssertionError(ioe);
        }

        return clone;
    }

    /**
     * Creates a slice of this index input, with the given description, offset, and length. The slice
     * is seeked to the beginning.
     */
    @Override
    public final CachedMemorySegmentIndexInput slice(String sliceDescription, long offset, long length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > this.length) {
            throw new IllegalArgumentException(
                "slice() "
                    + sliceDescription
                    + " out of bounds: offset="
                    + offset
                    + ",length="
                    + length
                    + ",fileLength="
                    + this.length
                    + ": "
                    + this
            );
        }

        if (FdcDebug.on(LOGGER)) {
            FdcDebug.count("input.slice");
            int callsite = FdcDebug.hotSite(LOGGER, "input.slice", path);
            FdcDebug
                .log(
                    LOGGER,
                    "fdc-debug input.slice from={} fromIsSlice={} skipCache={} off={} len={} desc={} path={} thread={} callsite={}{}",
                    System.identityHashCode(this),
                    isSlice,
                    skipCache,
                    offset,
                    length,
                    sliceDescription,
                    path,
                    FdcDebug.thread(),
                    callsite,
                    FdcDebug.poolState()
                );
        }
        var slice = buildSlice(sliceDescription, offset, length);

        slice.seek(0L);

        return slice;
    }

    /** Whether this input bypasses L1/L2. Visible for testing the inheritance contract in {@link #buildSlice}. */
    boolean isSkipCache() {
        return skipCache;
    }

    /**
     * Policy hook: should this DERIVED input bypass the block cache even though its parent does not?
     *
     * <p>Returning {@code false} means "inherit whatever the parent decided", which is the current
     * behaviour and the safe default. Returning {@code true} widens the bypass to this input and, because
     * the decision is inherited, to everything derived from it.
     *
     * <p><b>What is knowable here, and what is not.</b> This is the single funnel for every derived input -
     * {@code clone()} and both {@code slice()} overloads all route through {@link #buildSlice}, and for the
     * flows that matter (field data builds, merge reads) it is the ONLY seam they cross, because those
     * consumers never call {@code openInput} at all. So it is the right place for a decision. But the
     * caller's identity has already been lost by the time control arrives here: available are the parent's
     * path and extension, the region being derived, and the slice description. NOT available is who asked.
     *
     * <p>That matters because the same region of the same parent is derived by different consumers with
     * opposite requirements - measured: a field data build and a query-phase precompute both slice the
     * identical terms-index region from the same parent instance. A rule based only on the arguments below
     * therefore cannot separate "bulk one-shot reader" from "latency-sensitive search". Making this hook a
     * real policy needs intent supplied from above (a scoped marker set by the known bulk callers, or a
     * context-carrying slice overload), not a cleverer predicate here.
     *
     * @param sliceDescription the caller's slice label; {@code null} for {@code clone()}
     * @param absoluteOffset   absolute start offset of the derived region within the file
     * @param length           length of the derived region
     * @return {@code true} to bypass L1/L2 for this input; {@code false} to inherit the parent's decision
     */
    boolean enableSkipCache(String sliceDescription, long absoluteOffset, long length) {
        if (StaticConfigs.fieldDataStackDetectEnabled() == false) {
            return false;
        }
        String marker = fieldDataBuildFrameOnStack();
        if (marker == null) {
            return false;
        }
        // Make the totals available on a node that enabled only this experiment, without switching on the
        // whole fdc-debug stream. Idempotent.
        FdcDebug.enableCounting();
        // Logged at INFO and gated ONLY on the experiment flag, deliberately: on a node this is the whole
        // point of enabling the experiment, and requiring package-level DEBUG as well would drag in every
        // other trace statement in these packages. Volume is bounded by the number of field data build
        // derivations - single digits per (field, segment) - not by read volume, because a derived input
        // inherits the decision and never re-evaluates the hook.
        //
        // The matched frame is included as EVIDENCE. Without it the line asserts "this was a field data
        // build" and offers no way to check the claim; with it, a wrong match is visible in the log rather
        // than having to be reproduced under a debugger.
        LOGGER
            .info(
                "fdc-skipcache ENABLED reason=FIELD_DATA_STACK marker={} desc={} off={} len={} ext={} file={} thread={}",
                marker,
                sliceDescription,
                absoluteOffset,
                length,
                fdcExt,
                path.getFileName(),
                Thread.currentThread().getName()
            );
        return true;
    }

    /**
     * True when this derivation is happening inside a field data build.
     *
     * <p>Marker frame is {@code loadDirect} on a class under {@code org.opensearch.index.fielddata} -
     * {@code PagedBytesIndexFieldData.loadDirect} for text fields, its siblings for other field types.
     * That method IS the uninversion: its three statements produce every derived input a build makes
     * (estimator slice of the terms index, term-dictionary clone, postings clone). Matching on it therefore
     * catches the whole build and nothing else.
     *
     * <p>Deliberately NOT matching {@code IndicesFieldDataCache} alone. That class also appears on the stack
     * of a cache HIT, which performs no reads, and on the global-ordinals path, which builds an
     * {@code OrdinalMap} from already-cached leaves and likewise reads nothing. Keying on {@code loadDirect}
     * targets the reads specifically.
     *
     * <p>Verified against the traced chains: the field data build reaches this method with {@code loadDirect}
     * 6-8 filtered frames up, while the query-phase precompute path
     * ({@code GlobalOrdinalsStringTermsAggregator.tryCollectFromTermFrequencies}) derives the SAME region of
     * the SAME parent with no fielddata frame at all. So this predicate separates two consumers that no
     * argument-based rule could.
     *
     * <p>Short-circuits on the first match and stops after {@link #FIELD_DATA_STACK_MAX_FRAMES} frames, so
     * the common case (ordinary search, no match) walks a bounded prefix rather than the whole stack.
     */
    private static String fieldDataBuildFrameOnStack() {
        return StackWalker.getInstance().walk(frames -> frames.limit(FIELD_DATA_STACK_MAX_FRAMES).filter(f -> {
            if ("loadDirect".equals(f.getMethodName()) == false) {
                return false;
            }
            String cls = f.getClassName();
            return cls.startsWith("org.opensearch.index.fielddata") || cls.startsWith("org.opensearch.indices.fielddata");
        }).findFirst().map(f -> f.getClassName() + '.' + f.getMethodName() + ':' + f.getLineNumber()).orElse(null));
    }

    /**
     * Frame budget for {@link #isFieldDataBuildOnStack()}. The marker sits 6-8 filtered frames above the
     * derivation in the measured chains; unfiltered adds lambda and wrapper frames, so this is set well
     * clear of that. Too low silently produces false negatives (build not detected, no bypass); too high
     * only costs walk time on the miss path.
     */
    private static final int FIELD_DATA_STACK_MAX_FRAMES = 24;

    /** Builds the actual sliced IndexInput. * */
    CachedMemorySegmentIndexInput buildSlice(String sliceDescription, long sliceOffset, long length) {
        ensureOpen();
        // Calculate absolute base offset for the slice
        final long sliceAbsoluteBaseOffset = this.absoluteBaseOffset + sliceOffset;
        final String newResourceDescription = getFullSliceDescription(sliceDescription);

        // Bypass decision for the derived input: INHERIT the parent's, and let the hook ADD one.
        //
        // The OR is deliberate and one-way. Once an input is bypassing, none of its clones or slices has
        // any business re-entering the cache - the parent already declared these bytes not worth caching,
        // and a child that re-cached them would reintroduce exactly the eviction pressure the bypass exists
        // to remove. Equally important, replacing (rather than OR-ing) the inherited value silently
        // disables the bypass for every derived input: measured 44 masters against 21,648 derived inputs in
        // one merge test, so a non-inheriting version would apply the bypass to 0.2% of reads while
        // appearing to be enabled.
        final boolean hookWidened = skipCache == false && enableSkipCache(sliceDescription, sliceAbsoluteBaseOffset, length);
        final boolean shouldSkipCache = skipCache || hookWidened;
        if (hookWidened) {
            // Counted so an experiment can show WHICH derivations the hook caught, not just that it was on.
            FdcDebug.count("input.skipCache.hookWidened");
            FdcDebug.count("input.skipCache.hookWidened." + fdcExt);
            // No log line here: enableSkipCache() already emitted "fdc-skipcache ENABLED" with the matched
            // frame for this same event, and two records per decision only doubles the noise.
        }

        CachedMemorySegmentIndexInput slice = new CachedMemorySegmentIndexInput(
            newResourceDescription,
            path,
            sliceAbsoluteBaseOffset,
            length,
            blockCache,
            readaheadManager,
            readaheadContext,
            true,
            radixBlockTable,
            radixBlockTableRegistry, // slices share the table and registry for metrics, but don't call release()
            shouldSkipCache // inherited from the parent, possibly widened by enableSkipCache()
        );

        try {
            slice.seek(0L);
        } catch (IOException ioe) {
            throw new AssertionError(ioe);
        }

        return slice;
    }

    @Override
    public void prefetch(long offset, long length) throws IOException {
        ensureOpen();

        final long startFileOffset = absoluteBaseOffset + offset;
        final long startBlockOffset = startFileOffset & ~CACHE_BLOCK_MASK;
        final long endFileOffset = absoluteBaseOffset + offset + length;
        final long endBlockOffset = (endFileOffset + CACHE_BLOCK_MASK) & ~CACHE_BLOCK_MASK;
        final long blockCount = (endBlockOffset - startBlockOffset) >>> CACHE_BLOCK_SIZE_POWER;
        final long startBlockId = startBlockOffset >>> CACHE_BLOCK_SIZE_POWER;

        if (blockCount == 1) {
            if (radixBlockTable.get(startBlockId) != null) {
                return;
            }
        } else {
            // Find the first missing block in L1 cache. Sequential blockId access is
            // branch-predictor and CPU-prefetch friendly — RadixBlockTable.get() is two
            // plain array loads, no locks, no CAS.
            long firstMissing = blockCount; // sentinel: all present
            for (long i = 0; i < blockCount; i++) {
                if (radixBlockTable.get(startBlockId + i) == null) {
                    firstMissing = i;
                    break;
                }
            }
            if (firstMissing == blockCount) {
                return;
            }
            if (firstMissing > 0) {
                // Skip leading cached blocks — start loading from the first miss.
                // loadMissingBlocks submits the missing range to the shared prefetch ForkJoinPool
                // (async, fire-and-forget) and loads it into L2 (Caffeine); a subsequent read promotes
                // the block into L1 (RadixBlockTable) via acquireBlock().
                blockCache.loadMissingBlocks(path, startBlockOffset + (firstMissing << CACHE_BLOCK_SIZE_POWER), blockCount - firstMissing);
                return;
            }
        }

        // Submit the requested range to the prefetch executor; reads promote into L1 on access.
        blockCache.loadMissingBlocks(path, startBlockOffset, blockCount);
    }

    @Override
    @SuppressWarnings("ConvertToTryWithResources")
    public final void close() throws IOException {
        if (!isOpen) {
            return;
        }

        // fdc-debug (throwaway instrumentation, Track 17): REAL closes only. Deliberately placed
        // BELOW the isOpen guard so no-op double-closes are not counted - the opens-vs-closes
        // surplus arithmetic (surplus == handles still held) depends on that. isSlice separates the
        // master from clones/slices: clone() and slice() both go through buildSlice(.., true), and
        // only !isSlice does the real teardown (registry release + readaheadManager.close()).
        if (LOGGER.isDebugEnabled()) {
            String chain = fdcCallerChain(FDC_MAX_FRAMES);
            int closesite = chain.hashCode();
            if (FDC_SEEN_CLOSESITES.add(closesite)) {
                FdcDebug.log(LOGGER, "fdc-debug closesite NEW hash={} isSlice={} path={} chain={}", closesite, isSlice, path, chain);
            }
            FdcDebug
                .log(
                    LOGGER,
                    "fdc-debug close isSlice={} id={} path={} closesite={}",
                    isSlice,
                    System.identityHashCode(this),
                    path,
                    closesite
                );
        }

        // Mark as closed to ensure all future accesses throw AlreadyClosedException
        isOpen = false;

        // Release current block reference — GC handles cleanup
        currentBlock = null;
        currentBlockOffset = -1;
        currentBlockEnd = 0L;
        currentSegment = null;
        currentBlockStart = 0L;
        currentBlockStartRelative = 0L;

        if (!isSlice) {
            // Master instance cleanup
            if (radixBlockTableRegistry != null) {
                // Release our ref in the registry; when refCount reaches 0
                // the table is cleared and removed from the registry.
                radixBlockTableRegistry.release(path);
            }

            readaheadManager.close();
        }
        // Slices share cache, readahead manager, and radix table, so don't close them
    }
}
