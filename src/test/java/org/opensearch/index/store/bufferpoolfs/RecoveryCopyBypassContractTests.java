/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import java.nio.file.Path;

import org.apache.lucene.store.DataAccessHint;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.NoLockFactory;
import org.apache.lucene.store.ReadOnceHint;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.CryptoTestDirectoryFactory;
import org.opensearch.indices.replication.SegmentFileTransferHandlerCallerDouble;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Guards the peer-recovery-copy bypass in {@link BufferPoolDirectory#enableSkipBufferpool(String, IOContext)}
 * and, more importantly, the two <b>upstream contracts</b> it depends on.
 *
 * <h2>Why contract tests and not just behaviour tests</h2>
 * The bypass fires when a hint set by OpenSearch core meets a caller identified by name. Both are things this
 * plugin does not own:
 *
 * <ul>
 * <li><b>Core contract:</b> the copy's {@code openInput} carries {@link DataAccessHint#SEQUENTIAL}
 *     (set at {@code SegmentFileTransferHandler.onNewResource}). If a version bump drops that hint, or moves it
 *     onto some other flow, the bypass either stops working or starts working somewhere it should not.</li>
 * <li><b>Lucene contract:</b> a SEQUENTIAL-hinted context must stay distinguishable from
 *     {@link IOContext#READONCE}. The routing in {@code openInput} sends READONCE to the NIO path <em>before</em>
 *     the bypass decision is reached, so if the two ever became reference-equal — or if READONCE stopped
 *     carrying {@code ReadOnceHint} — the copy would silently leave the buffer-pool implementation entirely,
 *     which is the opposite of the intent (keep the DirectIO block path, skip only the caching).</li>
 * </ul>
 *
 * A behaviour test alone would pass while the mechanism quietly stopped applying. These assert the
 * assumptions, so a breaking upstream change fails a test here instead of turning into an unexplained
 * cache-hit-rate change in production.
 *
 * <p>The detection <em>fails open</em> by design: no hint, or an unrecognised caller, means the copy stays
 * pooled. Every negative case below therefore asserts a lost optimisation, never a correctness change.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class RecoveryCopyBypassContractTests extends OpenSearchTestCase {

    private static final IOContext SEQUENTIAL_CONTEXT = IOContext.DEFAULT.withHints(DataAccessHint.SEQUENTIAL);

    private BufferPoolDirectory directory;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        // Both global switches are consulted before the recovery clause, so they must be off or every case
        // below returns true for the wrong reason.
        StaticConfigs.setBlockCacheBypassEnabled(false);
        StaticConfigs.setSnapshotBypassEnabled(false);
        StaticConfigs.setRecoveryCopyBypassEnabled(true);
        Path path = createTempDir();
        directory = CryptoTestDirectoryFactory.createBufferPoolDirectory(path, NoLockFactory.INSTANCE);
    }

    @Override
    public void tearDown() throws Exception {
        StaticConfigs.setBlockCacheBypassEnabled(false);
        StaticConfigs.setSnapshotBypassEnabled(true);
        StaticConfigs.setRecoveryCopyBypassEnabled(false);
        if (directory != null) {
            directory.close();
        }
        super.tearDown();
    }

    // ---- Lucene contract ----

    /**
     * The hint we key on must be readable by TYPE from a plain DEFAULT context, and that context must not be
     * mistaken for READONCE by the reference comparison the routing uses.
     */
    public void testSequentialHintedContextIsDistinctFromReadOnce() {
        assertTrue("core's copy hint must be readable from the context", SEQUENTIAL_CONTEXT.hints().contains(DataAccessHint.SEQUENTIAL));
        assertFalse(
            "a SEQUENTIAL-hinted context must NOT carry ReadOnceHint, or MMapDirectory would confine the input to one thread",
            SEQUENTIAL_CONTEXT.hints().contains(ReadOnceHint.INSTANCE)
        );
        assertNotSame(
            "must not be reference-equal to READONCE: openInput routes READONCE to the NIO path before the bypass decision",
            IOContext.READONCE,
            SEQUENTIAL_CONTEXT
        );
        assertSame("hint set must not change the Context enum", IOContext.Context.DEFAULT, SEQUENTIAL_CONTEXT.context());
    }

    /**
     * Documents why the predicate reads hints by type rather than comparing against {@code IOContext.READONCE}:
     * READONCE <em>also</em> contains SEQUENTIAL, so a reference check would answer a different question.
     */
    public void testReadOnceAlsoCarriesSequentialWhichIsWhyWeMatchByType() {
        assertTrue(IOContext.READONCE.hints().contains(DataAccessHint.SEQUENTIAL));
        assertTrue(IOContext.READONCE.hints().contains(ReadOnceHint.INSTANCE));
    }

    // ---- caller detection ----

    /** The frame matcher must tolerate the anonymous-subclass suffix the real copy runs inside. */
    public void testFrameMatcherAcceptsAnonymousSubclassOfTheCopy() {
        assertTrue(
            BufferPoolDirectory.isRecoveryCopyFrame("org.opensearch.indices.replication.SegmentFileTransferHandler$1", "onNewResource")
        );
        assertTrue(
            BufferPoolDirectory.isRecoveryCopyFrame("org.opensearch.indices.replication.SegmentFileTransferHandler", "onNewResource")
        );
    }

    /** ...and must not fire for a different method on the same class, a different class, or nulls. */
    public void testFrameMatcherRejectsEverythingElse() {
        assertFalse(
            "another method on the copy class is not the per-file open",
            BufferPoolDirectory.isRecoveryCopyFrame("org.opensearch.indices.replication.SegmentFileTransferHandler$1", "nextChunkRequest")
        );
        assertFalse(
            "a same-named method elsewhere must not match",
            BufferPoolDirectory.isRecoveryCopyFrame("org.opensearch.index.engine.SomethingElse", "onNewResource")
        );
        assertFalse(BufferPoolDirectory.isRecoveryCopyFrame(null, "onNewResource"));
    }

    // ---- end-to-end predicate behaviour ----

    /**
     * The whole point of requiring the caller as well as the hint: a hinted open from anywhere else keeps its
     * cache. Without this, any future flow that upstream tags SEQUENTIAL would silently lose caching.
     */
    public void testHintAloneDoesNotBypass() {
        assertFalse(
            "SEQUENTIAL states an access pattern, not absence of reuse - the hint alone must not bypass",
            directory.enableSkipBufferpool("_0.cfs", SEQUENTIAL_CONTEXT)
        );
    }

    /** A copy-shaped caller without the hint also keeps its cache — both signals are required. */
    public void testRecoveryCallerWithoutHintDoesNotBypass() throws Exception {
        assertFalse(
            SegmentFileTransferHandlerCallerDouble.onNewResource(() -> directory.enableSkipBufferpool("_0.cfs", IOContext.DEFAULT))
        );
    }

    /** Both signals present: the copy bypasses. Exercises the real StackWalker, not a stand-in for it. */
    public void testHintPlusRecoveryCallerBypasses() throws Exception {
        assertTrue(
            "hint + recovery caller is the case the bypass exists for",
            SegmentFileTransferHandlerCallerDouble.onNewResource(() -> directory.enableSkipBufferpool("_0.cfs", SEQUENTIAL_CONTEXT))
        );
    }

    /** The flag is the kill switch and the A/B lever; off must mean off even when both signals are present. */
    public void testFlagOffDisablesTheBypassEntirely() throws Exception {
        StaticConfigs.setRecoveryCopyBypassEnabled(false);
        assertFalse(
            SegmentFileTransferHandlerCallerDouble.onNewResource(() -> directory.enableSkipBufferpool("_0.cfs", SEQUENTIAL_CONTEXT))
        );
    }

    /** An ordinary search-shaped open is untouched by any of this. */
    public void testPlainDefaultOpenStillPooled() {
        assertFalse(directory.enableSkipBufferpool("_0.cfs", IOContext.DEFAULT));
    }
}
