/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block;

import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import org.opensearch.index.store.block_cache.BlockCacheValue;
import org.opensearch.index.store.bufferpoolfs.StaticConfigs;

/**
 * A GC-managed wrapper around a direct {@link ByteBuffer} that implements {@link BlockCacheValue}.
 *
 * <p>All lifecycle methods are no-ops. The JVM's GC frees the backing
 * DirectByteBuffer when this object becomes unreachable. No ref counting,
 * no generation tracking, no close flag.
 *
 * <p>This replaces the older {@code RefCountedMemorySegment} recycle-based pool value: because
 * there is no wrapper to recycle out from under a reader, the segment-recycle race class
 * (a stale reference re-pinning recycled memory) is structurally impossible.
 *
 * @opensearch.internal
 */
public final class RefCountedByteBuffer implements BlockCacheValue<RefCountedByteBuffer> {

    private final ByteBuffer buffer;
    private final int length;
    private final MemorySegment segment;

    /**
     * True when this buffer is a transient, non-pooled fallback allocated by the read path because
     * the pool was exhausted/throttled (degraded mode). Such buffers are NOT counted in the pool's
     * {@code buffersInUse} accounting and MUST NOT be inserted into the block cache — caching them
     * would pin untracked direct memory on top of the pool. They are backed by a HEAP buffer (so they
     * draw from the GC heap, not the {@code -XX:MaxDirectMemorySize} budget that degraded mode is
     * recovering from) and back a single in-flight read; the JVM reclaims them by GC once the reader
     * drops them. They are never registered with the pool's Cleaner and never decrement buffersInUse.
     */
    private final boolean transientFallback;

    public RefCountedByteBuffer(ByteBuffer buffer, int length) {
        this(buffer, length, false);
    }

    /**
     * Creates a transient, non-cacheable fallback wrapper. See {@link #isTransientFallback()}.
     */
    public static RefCountedByteBuffer transientFallback(ByteBuffer buffer, int length) {
        return new RefCountedByteBuffer(buffer, length, true);
    }

    public RefCountedByteBuffer(ByteBuffer buffer, int length, boolean transientFallback) {
        this.buffer = buffer;
        this.length = length;
        this.transientFallback = transientFallback;
        // The global-arena optimization derives a native address, which is only valid for DIRECT
        // buffers — MemorySegment.ofBuffer(heap).address() throws UnsupportedOperationException. A
        // transient degraded-mode fallback is backed by a HEAP buffer (it must not draw from the
        // exhausted direct-memory budget), so always take the plain ofBuffer() branch for heap.
        if (buffer.isDirect() && StaticConfigs.memorySegmentGlobalArenaAndNormalizePathOptimEnabled()) {
            // Build the MemorySegment via ofAddress().reinterpret() so it is scoped to the
            // global arena (GlobalSession.GLOBAL), rather than a per-buffer GlobalSession
            // instance. The backing ByteBuffer is held by this.buffer, which keeps the
            // memory reachable for the lifetime of this wrapper.
            long address = MemorySegment.ofBuffer(buffer).address();
            this.segment = MemorySegment.ofAddress(address).reinterpret(length);
        } else {
            this.segment = MemorySegment.ofBuffer(buffer);
        }
    }

    public ByteBuffer buffer() {
        return buffer;
    }

    public MemorySegment segment() {
        return segment;
    }

    /** @return true if this is a transient, non-pooled, non-cacheable fallback buffer (degraded read). */
    public boolean isTransientFallback() {
        return transientFallback;
    }

    @Override
    public boolean isTransient() {
        return transientFallback;
    }

    @Override
    public RefCountedByteBuffer value() {
        return this;
    }

    @Override
    public int length() {
        return length;
    }

    @Override
    public int getGeneration() {
        return 0;
    }

    @Override
    public boolean tryPin() {
        return true;
    }

    @Override
    public void unpin() {}

    @Override
    public void decRef() {}

    @Override
    public void close() {}
}
