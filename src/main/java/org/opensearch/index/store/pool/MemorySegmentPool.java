/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.io.IOException;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.block.RefCountedByteBuffer;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;

/**
 * GC-managed pool for off-heap memory backed by direct {@link ByteBuffer}s.
 *
 * <p>Every {@link #tryAcquire} call allocates a fresh page-aligned {@link ByteBuffer#allocateDirect(int)}
 * wrapped in a {@link RefCountedByteBuffer} whose backing native memory is freed by the JVM's
 * {@link Cleaner} when the wrapper becomes unreachable. There is no freelist and no wrapper
 * recycling, which is what structurally eliminates the segment-recycle race class that the
 * earlier {@code RefCountedMemorySegment} pool was prone to.
 *
 * <h2>Back-pressure</h2>
 * Because buffers are allocated fresh and freed by GC rather than recycled through a bounded
 * freelist, memory use is not self-limiting; the pool layers two back-pressure mechanisms on top of
 * the JVM's own direct-memory accounting:
 * <ol>
 *   <li><b>Allocation limit / stall.</b> A {@link #buffersInUse} counter is incremented per
 *       acquire and decremented by the {@link Cleaner} on wrapper GC. When it would exceed
 *       {@code allocationLimit = maxSegments * (1 + gcHeadroomFraction)}, {@code tryAcquire}
 *       either fails fast (when {@link #stallLoopDisabled}) or spins up to the caller timeout
 *       waiting for GC to reclaim buffers.</li>
 *   <li><b>Memory-pressure throttle.</b> A background monitor thread sets a volatile
 *       {@code throttle} flag when either JVM free direct memory (via {@link BufferPoolMXBean})
 *       or OS free memory ({@code MemAvailable} from {@code /proc/meminfo}) drops below a reserve
 *       threshold. The reserve is a fraction of the corresponding budget rather than a flat
 *       constant: {@code max(256MB, 0.25 * MaxDirectMemorySize)} for direct memory and
 *       {@code max(256MB, 0.05 * totalMemory)} for OS memory. While engaged, {@code tryAcquire}
 *       rejects with {@link IOException}. The monitor also issues a {@code System.gc()} hint when
 *       "zombie" (GC-pending) buffers build up, to nudge reclamation.</li>
 * </ol>
 *
 * <p>Thread-safe. Rejections are reported as {@link IOException} so existing callers' generic
 * {@code catch (Exception | IOException)} blocks handle them uniformly.
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
@SuppressForbidden(reason = "Uses ByteBuffer.allocateDirect for native memory allocation")
public class MemorySegmentPool implements Pool<RefCountedByteBuffer>, AutoCloseable {

    private static final Logger LOGGER = LogManager.getLogger(MemorySegmentPool.class);
    private static final Cleaner CLEANER = Cleaner.create();

    /** Default GC headroom fraction: allocationLimit = maxSegments * (1 + this). */
    private static final double DEFAULT_GC_HEADROOM_FRACTION = 0.10;

    /**
     * Absolute FLOOR for the direct-memory throttle reserve. The effective threshold is
     * {@code max(THROTTLE_FREE_FLOOR_BYTES, THROTTLE_FREE_FRACTION * MaxDirectMemorySize)} — relative to the
     * node's direct-memory budget rather than a flat constant. A flat 500MB reserve was simultaneously far
     * too tight on large MaxDirect budgets (≈0.5%) and far too loose on tiny ones; worse, it was inconsistent
     * with the allocation limit (≈80% of MaxDirect), so on budgets under ~2.5GB the throttle fired before the
     * pool even reached its own limit. Tying the reserve to a fraction of MaxDirect keeps the two consistent.
     */
    static final long THROTTLE_FREE_FLOOR_BYTES = 256L * 1024 * 1024;
    /**
     * Direct-memory reserve as a fraction of MaxDirectMemorySize. Set ABOVE the pool's free-headroom at
     * its allocation limit so the throttle (and its coupled cache eviction) engages BEFORE acquisitions
     * start hitting the over-limit path. The pool's allocation limit is {@code pool_size_percentage *
     * (1 + gc_headroom_fraction)} of MaxDirect — with the defaults (0.70 and 0.10..0.1429) that is
     * 0.77..0.80 of MaxDirect, i.e. only 0.20..0.23 free at the limit. A 0.25 reserve therefore trips the
     * throttle just before the pool saturates, giving eviction a chance to relieve pressure rather than
     * letting callers stall/degrade. (A smaller reserve such as 0.10 would fire AFTER the limit — the
     * throttle/eviction would not engage when it is most needed.)
     */
    static final double THROTTLE_FREE_FRACTION = 0.25;

    /**
     * Absolute FLOOR for the OS-free throttle reserve. The effective threshold is
     * {@code max(OS_FREE_FLOOR_BYTES, OS_FREE_FRACTION * effectiveTotalMemory)}, where effectiveTotalMemory is
     * the cgroup memory limit when running in a container (see {@link #detectContainerMemoryLimitBytes()}), else
     * {@code MemTotal}. A flat 500MB was ~3.2% of a 15GB node (too tight — tripped under benign steady-state)
     * yet ~42% of a 1.2GB small node (absurdly loose). Container-awareness matters because {@code /proc/meminfo}
     * reports HOST memory, not the pod's cgroup budget.
     */
    static final long OS_FREE_FLOOR_BYTES = 256L * 1024 * 1024;
    /** OS-free reserve as a fraction of the effective (cgroup-aware) total memory. */
    static final double OS_FREE_FRACTION = 0.05;

    /** Effective direct-memory reserve, computed from MaxDirect at construction. */
    private final long throttleFreeBytes;

    private final int segmentSize;
    private final int maxSegments;
    private final long totalMemory;
    private final int allocationLimit;
    private final AtomicInteger buffersInUse = new AtomicInteger(0);
    private final LongAdder stallCount = new LongAdder();
    private final LongAdder gcTriggerCount = new LongAdder();

    // Previous cumulative snapshots for the throttle counters, so recordStats() publishes the PER-INTERVAL
    // delta (this tick minus last tick) rather than lifetime cumulative sums. Cumulative sums forced the
    // dashboard to derivative(), which mis-handles JVM-restart counter resets (large negative spikes). Only
    // read/written on the single-threaded telemetry tick, so no synchronization is needed.
    private long prevStallCount = 0L;
    private long prevGcTriggerCount = 0L;

    // GC hint controls.
    private volatile boolean gcHintEnabled = true;
    private volatile long gcHintCooldownNanos = 60L * 1_000_000_000L;
    /** Timestamp of most recent System.gc() hint; guards the cooldown gate. */
    private volatile long lastGcHintNanos = Long.MIN_VALUE / 2;

    /** Configurable OS free memory threshold; defaulted (cgroup-aware, relative) in the constructor. */
    private volatile long osFreeThresholdBytes;

    /**
     * When {@code true}, tryAcquire fails fast with a transient {@link IOException} when
     * buffersInUse exceeds allocationLimit instead of entering the bounded stall loop.
     *
     * <p>Defaults to {@code false}: over-limit acquisitions wait for GC/eviction to reclaim
     * buffers up to the caller's timeout rather than rejecting immediately. The previous
     * fail-fast default turned transient over-limit bursts (and, combined with the old
     * throttle gate, recovery reads) into hard failures. Operators can re-enable fast-fail
     * via {@link #setStallLoopDisabled(boolean)} where bounded latency is preferred over waiting.
     */
    private volatile boolean stallLoopDisabled = false;

    /** Set by the monitor when free direct memory or OS free memory drops below threshold. */
    private volatile boolean throttle = false;

    /** Which arm currently has the throttle engaged: "direct", "os", "direct+os", or "" when clear. Diagnostic. */
    private volatile String throttleArm = "";

    private volatile boolean closed = false;

    private final Thread gcDebtMonitor;
    private final BufferPoolMXBean directMemoryMxBean;
    private final long maxDirectMemoryBytes;
    private volatile LongSupplier cacheEntriesSupplier = () -> 0;

    /**
     * 1-second allocation/reclamation rate meter (bytes/sec). Fed on the acquire path
     * ({@link #onAllocated}) and the Cleaner path ({@link #onReclaimed}); snapshotted on the monitor
     * tick. Provides the trajectory signal for both the {@code crypto.pool.memory.stats} metric and
     * {@link ProactiveMemoryMonitor}. Initialized in the constructor so it shares the pool's clock seam.
     */
    private final AllocationRateMeter rateMeter;

    /** Proactive (preventive) cache-shrink monitor. Disabled by default; enabled via cluster setting. */
    private final ProactiveMemoryMonitor proactiveMonitor = new ProactiveMemoryMonitor();

    /**
     * Cleaner action: decrement the in-use counter AND record the reclamation for the rate meter, so a
     * lagging reclamation rate (GC not keeping up) is observable as the zombie-buildup precursor. Uses a
     * method reference (not a field-init lambda) so field access is deferred to call time — the lambda
     * form referenced the blank-final {@code rateMeter}/{@code segmentSize} before the ctor assigned them.
     */
    private final Runnable cleanerAction = this::onBufferReclaimed;

    private void onBufferReclaimed() {
        buffersInUse.decrementAndGet();
        rateMeter.onReclaimed(segmentSize);
    }

    /**
     * Invoked (best-effort) when the throttle TRANSITIONS from clear→engaged, to proactively release
     * pooled memory so the throttle can clear. Wired by {@code PoolBuilder} to invalidate a fraction of
     * the block cache (whose evicted entries' buffers then become unreachable and are reclaimed by the
     * Cleaner). Default no-op. This breaks the "sticky throttle" failure mode: the cache evicts by entry
     * count, not memory, and the {@code System.gc()} hint only fires on GC-pending "zombie" buffers — so
     * a legitimately-full cache under memory pressure would otherwise never release memory and the
     * throttle would stay engaged indefinitely, failing every recovery retry until the shard goes RED.
     */
    private volatile Runnable onThrottleEngagedHook = () -> {};

    /**
     * Proactive-shrink primitive: evict the given fraction of the coldest cached blocks, returning the
     * number evicted. Wired by {@code PoolBuilder} to {@code blockCache.evictColdestFraction}. Default
     * no-op (returns 0) so proactive shrink is inert until wired and until the cluster setting enables it.
     * Distinct from {@link #onThrottleEngagedHook}: this fires <em>preventively</em> (before the throttle),
     * the other fires reactively (after the throttle engaged).
     */
    private volatile java.util.function.DoubleFunction<Long> proactiveShrinkFn = f -> 0L;

    /** Original (boot-time) cache capacity in blocks; used by the proactive monitor's slack floor. Set by PoolBuilder. */
    private volatile long originalCacheMaxBlocks = 0L;

    /** Guards re-entrant / repeated cache-release while the throttle stays engaged. */
    private volatile long lastThrottleReleaseNanos = Long.MIN_VALUE / 2;
    /** Minimum spacing between throttle-triggered cache releases. */
    private volatile long throttleReleaseCooldownNanos = 2L * 1_000_000_000L;
    /** Count of consecutive 1Hz monitor ticks the throttle has stayed engaged; used to escalate relief + detect a stuck throttle. */
    private final AtomicInteger consecutiveThrottledTicks = new AtomicInteger(0);

    /**
     * Test seam — clock source. Defaults to {@link System#nanoTime()}. Package-private for tests.
     */
    private volatile LongSupplier clock = System::nanoTime;

    /**
     * Test seam — direct-memory allocator. Defaults to {@link #defaultAllocator(int)}.
     * Tests exercising the OOM path may override this.
     */
    private volatile TestAllocator allocator = MemorySegmentPool::defaultAllocator;

    /** Test seam — OS free memory supplier. When non-null, used instead of /proc/meminfo. */
    private volatile LongSupplier osFreeMemorySupplier = null;

    /**
     * Allocator function type used only by the test seam. Kept package-private so production
     * code cannot accidentally depend on it.
     */
    @FunctionalInterface
    interface TestAllocator {
        /** @throws OutOfMemoryError if direct memory is exhausted. */
        ByteBuffer allocate(int size);
    }

    /**
     * Default allocator — allocates exactly {@code size} bytes of direct memory.
     *
     * <p><b>No page-alignment over-allocation.</b> Pool buffers are used ONLY as in-memory copy
     * scratch for the block cache: every consumer touches them via {@link java.lang.foreign.MemorySegment#copy}
     * or {@code asSlice(0, ...)} (see {@code CryptoDirectIOBlockLoader} copy-into-pooled,
     * {@code BufferIOWithCaching} cache-warm, {@code CachedMemorySegmentIndexInput} read-back), none of
     * which require a page-aligned native address. The actual O_DIRECT DMA read uses its OWN
     * arena-allocated, page-aligned segment in {@code DirectIOReaderUtil.directIOReadAligned} and copies
     * the bytes into the pooled buffer afterwards — the pooled buffer never participates in DMA.
     *
     * <p>A prior version over-allocated by {@code pageSize - 1} bytes "for O_DIRECT alignment" and sliced
     * to a page-aligned offset. That alignment was never needed here, but it reserved {@code size + pageSize - 1}
     * bytes per block against {@code -XX:MaxDirectMemorySize} (≈ 1.5× for an 8KB block / 4KB page; up to 9× on
     * 64KB-page kernels) while {@link PoolSizeCalculator} and {@code buffersInUse * segmentSize} accounted for
     * only {@code size}. The result was real direct-memory reservation of ≈ 1.5× the configured pool, breaching
     * {@code MaxDirectMemorySize} as the cache filled and tripping the memory-pressure throttle under sustained
     * load (shard recovery RED). Allocating exactly {@code size} makes the accounting accurate.
     *
     * <p>{@code allocateDirect} still invokes {@code Bits.reserveMemory}, so {@link BufferPoolMXBean} (used by
     * the monitor) and {@code -XX:MaxDirectMemorySize} continue to track and bound pool allocations; the
     * Cleaner frees the buffer when its wrapper becomes unreachable.
     */
    private static ByteBuffer defaultAllocator(int size) {
        return ByteBuffer.allocateDirect(size).order(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Creates a pool sized by {@code totalMemory}, each segment {@code segmentSize} bytes, using
     * the default GC headroom fraction.
     *
     * @param totalMemory total pool memory in bytes (must be a multiple of segmentSize)
     * @param segmentSize size of each segment in bytes
     */
    public MemorySegmentPool(long totalMemory, int segmentSize) {
        this(totalMemory, segmentSize, DEFAULT_GC_HEADROOM_FRACTION);
    }

    /**
     * Creates a pool with an explicit GC headroom fraction.
     *
     * @param totalMemory total pool memory in bytes (must be a multiple of segmentSize)
     * @param segmentSize size of each segment in bytes
     * @param gcHeadroomFraction allocationLimit = maxSegments * (1 + this); absorbs GC-pending
     *                           "zombie" wrappers before the stall path engages
     */
    public MemorySegmentPool(long totalMemory, int segmentSize, double gcHeadroomFraction) {
        if (totalMemory % segmentSize != 0) {
            throw new IllegalArgumentException("Total memory must be a multiple of segment size");
        }
        this.directMemoryMxBean = ManagementFactory
            .getPlatformMXBeans(BufferPoolMXBean.class)
            .stream()
            .filter(p -> "direct".equals(p.getName()))
            .findFirst()
            .orElse(null);
        this.maxDirectMemoryBytes = readMaxDirectMemorySize();
        this.totalMemory = totalMemory;
        this.segmentSize = segmentSize;
        this.maxSegments = (int) (totalMemory / segmentSize);
        this.allocationLimit = maxSegments + (int) (maxSegments * gcHeadroomFraction);

        // Relative, container-aware throttle thresholds (see field docs). Direct-memory reserve scales with
        // MaxDirect (kept consistent with the ≈80%-of-MaxDirect allocation limit); OS-free reserve scales with
        // the cgroup memory limit when containerized, else MemTotal — with absolute floors so tiny nodes are sane.
        this.throttleFreeBytes = maxDirectMemoryBytes > 0
            ? Math.max(THROTTLE_FREE_FLOOR_BYTES, (long) (maxDirectMemoryBytes * THROTTLE_FREE_FRACTION))
            : THROTTLE_FREE_FLOOR_BYTES;
        long effectiveTotal = detectContainerMemoryLimitBytes();
        this.osFreeThresholdBytes = effectiveTotal > 0
            ? Math.max(OS_FREE_FLOOR_BYTES, (long) (effectiveTotal * OS_FREE_FRACTION))
            : OS_FREE_FLOOR_BYTES;

        // Defer to the (swappable) clock field so tests that install a TestClock also drive the meter.
        this.rateMeter = new AllocationRateMeter(() -> clock.getAsLong());

        this.gcDebtMonitor = new Thread(this::gcDebtMonitorLoop, "pool-gc-debt-monitor");
        gcDebtMonitor.setDaemon(true);
        gcDebtMonitor.start();
        LOGGER
            .info(
                "MemorySegmentPool: maxSegments={}, allocationLimit={}, gcHeadroomFraction={}, "
                    + "throttleFreeReserve={}MB (maxDirect={}MB), osFreeReserve={}MB (effectiveTotal={}MB)",
                maxSegments,
                allocationLimit,
                gcHeadroomFraction,
                throttleFreeBytes / (1024 * 1024),
                maxDirectMemoryBytes / (1024 * 1024),
                osFreeThresholdBytes / (1024 * 1024),
                effectiveTotal / (1024 * 1024)
            );
    }

    /** Register cache size supplier for GC debt monitoring (typically blockCache::getCacheSize). */
    public void setCacheEntriesSupplier(LongSupplier supplier) {
        this.cacheEntriesSupplier = supplier;
    }

    /**
     * Register a best-effort hook invoked when the throttle engages (clear→engaged transition), to
     * proactively release pooled memory (e.g. invalidate a fraction of the block cache) so the throttle
     * can clear. See {@link #onThrottleEngagedHook}. Pass {@code null} to reset to no-op.
     */
    public void setOnThrottleEngagedHook(Runnable hook) {
        this.onThrottleEngagedHook = hook != null ? hook : () -> {};
    }

    /**
     * Wire the proactive-shrink primitive (typically {@code blockCache::evictColdestFraction}) and the
     * original cache capacity used by the proactive monitor's slack floor. Pass {@code null} to reset
     * to the no-op (proactive shrink then evicts nothing even when the cluster setting is enabled).
     */
    public void setProactiveShrink(java.util.function.DoubleFunction<Long> shrinkFn, long originalCacheMaxBlocks) {
        this.proactiveShrinkFn = shrinkFn != null ? shrinkFn : f -> 0L;
        this.originalCacheMaxBlocks = originalCacheMaxBlocks;
    }

    /** Enable/disable System.gc() hints at runtime. */
    public void setGcHintEnabled(boolean enabled) {
        this.gcHintEnabled = enabled;
    }

    /** Update the minimum seconds between consecutive System.gc() hints. */
    public void setGcHintCooldownSeconds(long seconds) {
        this.gcHintCooldownNanos = seconds * 1_000_000_000L;
    }

    /** Update the OS free memory throttle threshold at runtime. */
    public void setOsFreeThresholdBytes(long bytes) {
        this.osFreeThresholdBytes = bytes;
        LOGGER.info("OS free memory throttle threshold set to {}MB", bytes / (1024 * 1024));
    }

    /** Current OS free memory throttle threshold in bytes. */
    public long getOsFreeThresholdBytes() {
        return osFreeThresholdBytes;
    }

    /** Enable/disable the stall loop. When disabled, over-limit allocations fail fast. */
    public void setStallLoopDisabled(boolean disabled) {
        LOGGER.info("Stall loop {}", disabled ? "DISABLED (fail-fast)" : "ENABLED (bounded wait)");
        this.stallLoopDisabled = disabled;
    }

    public boolean isStallLoopDisabled() {
        return stallLoopDisabled;
    }

    public boolean isThrottleEngaged() {
        return throttle;
    }

    // ---- Test seams (package-private, never wired from production) -----------------------

    void setClockForTesting(LongSupplier clock) {
        this.clock = clock != null ? clock : System::nanoTime;
    }

    void setAllocatorForTesting(TestAllocator allocator) {
        this.allocator = allocator != null ? allocator : MemorySegmentPool::defaultAllocator;
    }

    void setOsFreeMemorySupplierForTesting(LongSupplier supplier) {
        this.osFreeMemorySupplier = supplier;
    }

    @Override
    public RefCountedByteBuffer tryAcquire(long timeout, TimeUnit unit) throws Exception {
        if (closed) {
            throw new IllegalStateException("Pool is closed");
        }

        // Single bounded-wait loop honoring the caller's deadline for BOTH back-pressure signals:
        // the memory-pressure throttle and the allocation-limit. Critically, the throttle is no
        // longer an instant-reject gate ahead of the timeout — a transient dip (the monitor clears
        // the throttle at 1Hz; throttle-coupled eviction releases memory) is ridden out within the
        // caller's budget. A recovery read passes a multi-second timeout and survives a brief
        // throttle (so it no longer turns a transient dip into a fatal RecoveryFailedException / RED);
        // prefetch passes ~50ms and still fails fast, as intended.
        final long deadlineNanos = clock.getAsLong() + unit.toNanos(timeout);
        boolean counted = false;
        while (true) {
            if (closed) {
                throw new IllegalStateException("Pool is closed");
            }

            if (throttle) {
                long remainingNanos = deadlineNanos - clock.getAsLong();
                if (remainingNanos <= 0) {
                    if (!counted) {
                        stallCount.increment();
                    }
                    String arm = throttleArm;
                    CryptoMetricsService.getInstance().recordError(ErrorType.POOL_ACQUIRE_TIMEOUT_THROTTLE);
                    throw new IOException(
                        "Memory-pressure throttle engaged (arm="
                            + (arm.isEmpty() ? "unknown" : arm)
                            + ", directReserve="
                            + (throttleFreeBytes / (1024 * 1024))
                            + "MB, osReserve="
                            + (osFreeThresholdBytes / (1024 * 1024))
                            + "MB) after waiting "
                            + unit.toMillis(timeout)
                            + "ms for release"
                    );
                }
                if (!counted) {
                    stallCount.increment();
                    counted = true;
                }
                Thread.sleep(Math.min(TimeUnit.NANOSECONDS.toMillis(remainingNanos), 10));
                continue;
            }

            if (buffersInUse.incrementAndGet() <= allocationLimit) {
                return allocateAndWrap();   // OOM propagates as-is (direct-memory exhaustion)
            }
            buffersInUse.decrementAndGet();

            // Over the allocation limit. Fail-fast only if explicitly configured (off by default);
            // otherwise wait for GC/eviction to reclaim buffers, up to the caller's deadline.
            if (stallLoopDisabled) {
                if (!counted) {
                    stallCount.increment();
                }
                CryptoMetricsService.getInstance().recordError(ErrorType.POOL_ACQUIRE_TIMEOUT_STALL_DISABLED);
                throw new IOException(
                    "Pool over limit (stall loop disabled) (inUse=" + buffersInUse.get() + ", limit=" + allocationLimit + ")"
                );
            }

            long remainingNanos = deadlineNanos - clock.getAsLong();
            if (remainingNanos <= 0) {
                if (!counted) {
                    stallCount.increment();
                }
                CryptoMetricsService.getInstance().recordError(ErrorType.POOL_ACQUIRE_TIMEOUT_ALLOCATION_LIMIT);
                throw new IOException(
                    "Pool acquisition timed out after "
                        + unit.toMillis(timeout)
                        + "ms"
                        + " (inUse="
                        + buffersInUse.get()
                        + ", max="
                        + maxSegments
                        + ", limit="
                        + allocationLimit
                        + ")"
                );
            }
            if (!counted) {
                stallCount.increment();
                counted = true;
            }
            Thread.sleep(Math.min(TimeUnit.NANOSECONDS.toMillis(remainingNanos), 10));
        }
    }

    /**
     * Shared allocation+wrap helper. Assumes the caller has already incremented
     * {@link #buffersInUse} and verified it is &le; {@link #allocationLimit}.
     *
     * <p>On {@link OutOfMemoryError} from {@code allocateDirect}, the counter is decremented and the
     * OOM propagates as-is so the JVM's direct-memory accounting/handling is preserved.
     */
    private RefCountedByteBuffer allocateAndWrap() throws IOException {
        final ByteBuffer buf;
        try {
            // INVARIANT: this try body must contain ONLY the direct-memory allocation call so an
            // OutOfMemoryError observed here is unambiguously direct-memory exhaustion.
            buf = allocator.allocate(segmentSize);
        } catch (OutOfMemoryError e) {
            buffersInUse.decrementAndGet();
            throw e;   // propagate OOM as-is
        }
        rateMeter.onAllocated(segmentSize);
        return wrapAndRegister(buf);
    }

    /** Proactive cache-shrink monitor (accessor so the cluster setting can flip it at runtime). */
    public ProactiveMemoryMonitor proactiveMonitor() {
        return proactiveMonitor;
    }

    private RefCountedByteBuffer wrapAndRegister(ByteBuffer direct) {
        RefCountedByteBuffer wrapper = new RefCountedByteBuffer(direct, segmentSize);
        CLEANER.register(wrapper, cleanerAction);
        return wrapper;
    }

    @Override
    public void release(RefCountedByteBuffer refSegment) {
        // No-op: Cleaner handles lifecycle when wrapper is GC'd.
    }

    public void releaseAll(RefCountedByteBuffer... segments) {
        // No-op
    }

    @Override
    public long totalMemory() {
        return totalMemory;
    }

    @Override
    public long availableMemory() {
        return (long) Math.max(0, maxSegments - buffersInUse.get()) * segmentSize;
    }

    @Override
    public int pooledSegmentSize() {
        return segmentSize;
    }

    public int getBuffersInUse() {
        return buffersInUse.get();
    }

    public long getAllocatedBytes() {
        return (long) buffersInUse.get() * segmentSize;
    }

    @Override
    public boolean isUnderPressure() {
        return buffersInUse.get() >= (int) (maxSegments * 0.95);
    }

    @Override
    public void warmUp(long targetSegments) {
        // No-op: byte buffers don't require warmup.
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        gcDebtMonitor.interrupt();
        try {
            gcDebtMonitor.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        LOGGER.info("MemorySegmentPool closed");
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public String poolStats() {
        int inUse = getBuffersInUse();
        long trackedBytes = getAllocatedBytes();
        long nativeUsed = getDirectMemoryUsed();
        long zombieBytes = nativeUsed >= 0 ? nativeUsed - trackedBytes : -1;
        return String
            .format(
                "PoolStats[max=%d, inUse=%d, utilization=%.1f%%, stalls=%d, tracked=%dMB, native=%dMB, zombie=%dMB]",
                maxSegments,
                inUse,
                maxSegments > 0 ? (double) inUse / maxSegments * 100 : 0,
                stallCount.sum(),
                trackedBytes / (1024 * 1024),
                nativeUsed / (1024 * 1024),
                zombieBytes / (1024 * 1024)
            );
    }

    @Override
    public void recordStats() {
        int inUse = buffersInUse.get();
        int free = Math.max(0, maxSegments - inUse);
        double utilization = maxSegments > 0 ? (double) inUse / maxSegments : 0;
        double allocation = utilization;
        CryptoMetricsService.getInstance().recordPoolStats(SegmentType.PRIMARY, maxSegments, inUse, free, utilization, allocation);
        // Emit the back-pressure mechanism state so the exact RED-prevention machinery (throttle/stall/gc)
        // can be dashboarded/alarmed on, not just pool occupancy. stall_count and gc_trigger_count are
        // published as PER-INTERVAL deltas (since the last tick), not lifetime cumulative sums — see the
        // prevStallCount/prevGcTriggerCount fields; throttle_engaged is an instantaneous 0/1 gauge.
        long stalls = stallCount.sum();
        long gcTriggers = gcTriggerCount.sum();
        long deltaStalls = stalls - prevStallCount;
        long deltaGcTriggers = gcTriggers - prevGcTriggerCount;
        prevStallCount = stalls;
        prevGcTriggerCount = gcTriggers;
        CryptoMetricsService.getInstance().recordThrottleStats(throttle ? 1 : 0, throttleArm, deltaStalls, deltaGcTriggers);

        // Refresh the 1s alloc/reclaim rate gauges from the cumulative deltas since the last tick.
        rateMeter.snapshot();

        // Emit the memory-pressure causal factors — the "why did it throttle" post-mortem set. These are
        // leading indicators (direct/os headroom trend, zombie bytes, alloc/reclaim trajectory) that are
        // otherwise only in log lines, so an incident could see the throttle fire but not the run-up to it.
        long directUsed = getDirectMemoryUsed();
        long trackedBytes = (long) inUse * segmentSize;
        long zombieBytes = directUsed >= 0 ? Math.max(0, directUsed - trackedBytes) : -1;
        long directHeadroom = (maxDirectMemoryBytes > 0 && directUsed >= 0) ? maxDirectMemoryBytes - directUsed : -1;
        long osFree = readMemAvailable();
        long osHeadroom = osFree >= 0 ? osFree - osFreeThresholdBytes : -1;
        long allocRate = rateMeter.allocationRateBytesPerSec();
        long reclaimRate = rateMeter.reclamationRateBytesPerSec();
        CryptoMetricsService
            .getInstance()
            .recordMemoryStats(
                directUsed,
                maxDirectMemoryBytes,
                directHeadroom,
                zombieBytes,
                osFree,
                osHeadroom,
                allocRate,
                reclaimRate,
                consecutiveThrottledTicks.get()
            );

        // Proactive (preventive) cache shrink: while memory is still healthy but on a filling trajectory,
        // give back excess cache early so natural GC keeps up and the throttle ideally never engages.
        // Disabled by default (cluster setting); a no-op shrink primitive until wired by PoolBuilder.
        try {
            proactiveMonitor
                .evaluateAndMaybeShrink(
                    inUse,
                    allocationLimit,
                    allocRate,
                    reclaimRate,
                    cacheEntriesSupplier.getAsLong(),
                    originalCacheMaxBlocks,
                    proactiveShrinkFn
                );
        } catch (Throwable t) {
            LOGGER.warn("Proactive cache-shrink evaluation failed", t);
        }
    }

    public long getDirectMemoryUsed() {
        return directMemoryMxBean != null ? directMemoryMxBean.getMemoryUsed() : -1;
    }

    public long getStallCount() {
        return stallCount.sum();
    }

    public long getGcTriggerCount() {
        return gcTriggerCount.sum();
    }

    // ---- Background monitor (memory-pressure throttle + legacy GC hint) -----------------

    private void gcDebtMonitorLoop() {
        int tick = 0;
        while (!closed) {
            try {
                Thread.sleep(100);
                tick++;
                // Every tick (100ms): lightweight OS free memory check (can only SET throttle).
                checkOsFreeMemory();
                // Every 10th tick (1s): full check (direct-memory MXBean + GC hint).
                if (tick % 10 == 0) {
                    checkGcDebt();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Throwable t) {
                LOGGER.warn("Error in GC debt monitor", t);
            }
        }
    }

    private volatile boolean osFreeMemoryChecked = false;

    /**
     * Lightweight OS free memory check (10 Hz). Reads MemAvailable from /proc/meminfo.
     * Can SET throttle but cannot CLEAR it — only {@link #checkGcDebt()} is authoritative.
     */
    void checkOsFreeMemory() {
        long osFree = readMemAvailable();
        if (!osFreeMemoryChecked) {
            osFreeMemoryChecked = true;
            if (osFree < 0) {
                LOGGER
                    .warn(
                        "OS free memory monitoring UNAVAILABLE: /proc/meminfo not readable. "
                            + "OS-level throttle disabled; only direct-memory throttle is active."
                    );
            } else {
                LOGGER
                    .info(
                        "OS free memory monitoring active: MemAvailable={}MB, threshold={}MB",
                        osFree / (1024 * 1024),
                        osFreeThresholdBytes / (1024 * 1024)
                    );
            }
        }
        if (osFree < 0) {
            return;
        }
        if (osFree < osFreeThresholdBytes && !throttle) {
            throttle = true;
            LOGGER
                .warn(
                    "OS free memory throttle ENGAGED: free={}MB threshold={}MB",
                    osFree / (1024 * 1024),
                    osFreeThresholdBytes / (1024 * 1024)
                );
        }
    }

    /**
     * Reads MemAvailable from /proc/meminfo. Returns -1 on failure (non-Linux or parse error).
     */
    @SuppressForbidden(reason = "Reads /proc/meminfo for OS-level free memory monitoring")
    static long readMemAvailableFromProc() {
        try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader("/proc/meminfo"), 1024)) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("MemAvailable:")) {
                    String[] parts = line.split("\\s+");
                    return Long.parseLong(parts[1]) * 1024; // kB to bytes
                }
            }
        } catch (Exception e) {
            // Non-Linux or permission error — degrade gracefully
        }
        return -1;
    }

    /** Read OS free memory — uses test seam if set, otherwise /proc/meminfo. */
    long readMemAvailable() {
        LongSupplier supplier = osFreeMemorySupplier;
        return supplier != null ? supplier.getAsLong() : readMemAvailableFromProc();
    }

    /**
     * Full debt check (1 Hz). Authoritative throttle writer (SET and CLEAR) based on direct
     * memory + OS free memory, plus the legacy {@code System.gc()} hint on zombie buildup.
     */
    void checkGcDebt() {
        if (closed) {
            return;
        }
        int inUse = buffersInUse.get();
        long cacheEntries = cacheEntriesSupplier.getAsLong();
        long zombies = inUse - cacheEntries;
        int remaining = allocationLimit - inUse;

        long used = getDirectMemoryUsed();
        long osFree = readMemAvailable();
        boolean directHit = shouldThrottleDirect(used, maxDirectMemoryBytes, throttleFreeBytes);
        boolean osHit = shouldThrottleOs(osFree, osFreeThresholdBytes);
        boolean newThrottle = directHit || osHit;
        // Record which arm engaged so the rejection IOException can name the real cause (rather than a
        // fixed "direct memory" message regardless of which check fired).
        this.throttleArm = !newThrottle ? "" : (directHit && osHit ? "direct+os" : directHit ? "direct" : "os");
        if (newThrottle != throttle) {
            LOGGER
                .warn(
                    "Throttle {} [{}]: direct(max={}MB used={}MB reserve={}MB) os(free={}MB threshold={}MB)",
                    newThrottle ? "ENGAGED" : "RELEASED",
                    newThrottle ? throttleArm : "-",
                    maxDirectMemoryBytes / (1024 * 1024),
                    used / (1024 * 1024),
                    throttleFreeBytes / (1024 * 1024),
                    osFree >= 0 ? osFree / (1024 * 1024) : -1,
                    osFreeThresholdBytes / (1024 * 1024)
                );
            if (newThrottle) {
                // Low-latency signal on the clear->engaged edge so an alarm fires immediately rather than
                // waiting for the next (5-min) telemetry tick. Best-effort: never let metrics break the pool.
                try {
                    CryptoMetricsService.getInstance().recordThrottleEngaged(throttleArm);
                } catch (Exception ignore) {
                    // metrics not initialized / registry error — non-fatal
                }
            }
        }
        throttle = newThrottle;

        // While the throttle is engaged, proactively release pooled memory so it can clear. The cache
        // evicts by entry COUNT (not memory) and the System.gc() hint below only fires on GC-pending
        // "zombie" buffers — so a legitimately-full cache under memory pressure would never shrink and
        // the throttle would stay stuck, failing every recovery retry until the shard goes RED. We
        // invoke the release hook on every engaged tick, cooldown-gated to avoid thrashing, until the
        // pressure subsides and the throttle clears.
        if (newThrottle) {
            int ticks = consecutiveThrottledTicks.incrementAndGet();
            long now = clock.getAsLong();
            if (now - lastThrottleReleaseNanos >= throttleReleaseCooldownNanos) {
                lastThrottleReleaseNanos = now;
                try {
                    onThrottleEngagedHook.run();
                } catch (Throwable t) {
                    LOGGER.warn("Throttle-engaged cache-release hook failed", t);
                }
            }
            // Escalation: eviction only makes the cache's wrappers UNREACHABLE; their backing direct
            // memory is freed when the Cleaner runs (GC-timed), so memory may not visibly drop for
            // several ticks. If the throttle has stayed engaged for a sustained window despite eviction,
            // nudge a GC (cooldown-gated) so the evicted buffers are actually reclaimed and the throttle
            // can clear — and surface a WARN so a genuinely stuck throttle is observable.
            if (ticks >= 3 && gcHintEnabled && (now - lastGcHintNanos >= gcHintCooldownNanos)) {
                LOGGER.warn("Throttle still engaged after {} ticks [{}] — nudging GC to reclaim evicted buffers", ticks, throttleArm);
                System.gc();
                gcTriggerCount.increment();
                lastGcHintNanos = now;
            }
        } else {
            consecutiveThrottledTicks.set(0);
        }

        // Legacy System.gc() hint when zombies exceed 5% of allocationLimit AND remaining
        // capacity drops below 10% — nudges reclamation of GC-pending direct buffers.
        if (zombies > allocationLimit / 20 && remaining < allocationLimit / 10) {
            if (gcHintEnabled) {
                long now = clock.getAsLong();
                if (now - lastGcHintNanos >= gcHintCooldownNanos) {
                    LOGGER
                        .debug(
                            "GC debt: triggering System.gc() — inUse={}, cacheEntries={}, zombies={}, remaining={}/{}",
                            inUse,
                            cacheEntries,
                            zombies,
                            remaining,
                            allocationLimit
                        );
                    System.gc();
                    gcTriggerCount.increment();
                    lastGcHintNanos = now;
                }
            }
        }
    }

    /**
     * Returns true if the pool should throttle new acquisitions based on memory pressure.
     * Dual threshold: either direct-memory headroom OR OS-level free memory being breached
     * triggers throttle.
     */
    static boolean shouldThrottle(long directUsed, long maxDirectMemoryBytes, long osFreeBytes) {
        return shouldThrottleDirect(directUsed, maxDirectMemoryBytes) || shouldThrottleOs(osFreeBytes);
    }

    /**
     * Direct-memory-only throttle decision (no OS free memory signal). Convenience overload
     * for callers and tests that only have the direct-memory reading.
     */
    static boolean shouldThrottle(long used, long maxDirectMemoryBytes) {
        return shouldThrottleDirect(used, maxDirectMemoryBytes);
    }

    /** Direct-memory throttle decision with an explicit reserve threshold. */
    static boolean shouldThrottleDirect(long used, long maxDirectMemoryBytes, long reserveBytes) {
        if (maxDirectMemoryBytes <= 0 || used < 0) {
            return false;
        }
        return (maxDirectMemoryBytes - used) < reserveBytes;
    }

    /** Convenience overload using the absolute reserve floor (used by static-helper tests). */
    static boolean shouldThrottleDirect(long used, long maxDirectMemoryBytes) {
        return shouldThrottleDirect(used, maxDirectMemoryBytes, THROTTLE_FREE_FLOOR_BYTES);
    }

    /** Returns true if OS free memory (MemAvailable) is below the given threshold. */
    static boolean shouldThrottleOs(long osFreeBytes, long thresholdBytes) {
        if (osFreeBytes < 0) {
            return false; // unknown — don't throttle
        }
        return osFreeBytes < thresholdBytes;
    }

    /** Convenience overload using the absolute OS-free reserve floor. */
    static boolean shouldThrottleOs(long osFreeBytes) {
        return shouldThrottleOs(osFreeBytes, OS_FREE_FLOOR_BYTES);
    }

    /**
     * Best-effort detection of the effective memory limit the process runs under: the cgroup memory
     * limit when containerized (so the OS-free reserve reflects the POD budget, not the host that
     * {@code /proc/meminfo} reports), else {@code MemTotal}. Returns &le;0 if nothing is detectable
     * (caller falls back to the absolute floor). cgroup v2 ({@code /sys/fs/cgroup/memory.max}) is tried
     * first, then v1 ({@code /sys/fs/cgroup/memory/memory.limit_in_bytes}); an absent/"max"/host-sized
     * value is treated as "no container cap" in favour of {@code MemTotal}.
     */
    @SuppressForbidden(reason = "Reads cgroup + /proc/meminfo for container-aware memory limit detection")
    static long detectContainerMemoryLimitBytes() {
        long memTotal = readMemTotalFromProc();
        long cgroup = readCgroupMemoryLimitBytes();
        if (cgroup > 0 && (memTotal <= 0 || cgroup < memTotal)) {
            return cgroup;
        }
        return memTotal;
    }

    @SuppressForbidden(reason = "Reads cgroup memory limit files for container-aware throttling")
    private static long readCgroupMemoryLimitBytes() {
        long v2 = readLongFromFile("/sys/fs/cgroup/memory.max");           // cgroup v2
        if (v2 > 0) {
            return v2;
        }
        long v1 = readLongFromFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); // cgroup v1
        if (v1 > 0 && v1 < (1L << 62)) {                                  // v1 "no limit" is a huge sentinel
            return v1;
        }
        return -1;
    }

    @SuppressForbidden(reason = "Reads a cgroup/proc numeric file")
    private static long readLongFromFile(String path) {
        try {
            String s = new String(
                java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)),
                java.nio.charset.StandardCharsets.US_ASCII
            ).trim();
            if (s.isEmpty() || "max".equals(s)) {
                return -1; // cgroup v2 "max" == no limit
            }
            return Long.parseLong(s);
        } catch (Exception e) {
            return -1;
        }
    }

    @SuppressForbidden(reason = "Reads /proc/meminfo MemTotal")
    private static long readMemTotalFromProc() {
        try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader("/proc/meminfo"), 1024)) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("MemTotal:")) {
                    return Long.parseLong(line.split("\\s+")[1]) * 1024; // kB → bytes
                }
            }
        } catch (Exception e) {
            // non-Linux or unreadable
        }
        return -1;
    }

    /** Read -XX:MaxDirectMemorySize from JVM args; returns 0 if not set. */
    private static long readMaxDirectMemorySize() {
        return ManagementFactory
            .getRuntimeMXBean()
            .getInputArguments()
            .stream()
            .filter(arg -> arg.startsWith("-XX:MaxDirectMemorySize="))
            .map(arg -> parseSize(arg.substring("-XX:MaxDirectMemorySize=".length())))
            .reduce((a, b) -> b)
            .orElse(0L);
    }

    private static long parseSize(String value) {
        value = value.trim().toLowerCase(java.util.Locale.ROOT);
        long multiplier = 1;
        if (value.endsWith("k")) {
            multiplier = 1024L;
            value = value.substring(0, value.length() - 1);
        } else if (value.endsWith("m")) {
            multiplier = 1024L * 1024;
            value = value.substring(0, value.length() - 1);
        } else if (value.endsWith("g")) {
            multiplier = 1024L * 1024 * 1024;
            value = value.substring(0, value.length() - 1);
        }
        try {
            return Long.parseLong(value) * multiplier;
        } catch (NumberFormatException e) {
            return 0L;
        }
    }
}
