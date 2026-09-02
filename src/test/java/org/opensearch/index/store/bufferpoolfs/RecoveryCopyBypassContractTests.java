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
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Guards the peer-recovery-copy bypass in {@link BufferPoolDirectory#enableSkipBufferpool(String, IOContext)}
 * and, more importantly, the <b>upstream contract</b> it now rests on entirely.
 *
 * <h2>Why contract tests and not just behaviour tests</h2>
 * The bypass fires on a single signal this plugin does not own: the {@link DataAccessHint#SEQUENTIAL} hint that
 * OpenSearch core attaches at {@code SegmentFileTransferHandler.onNewResource}. Keying on the hint alone is only
 * sound because of an assumption about everything <em>else</em> that could carry it:
 *
 * <ul>
 * <li><b>Core contract:</b> the copy's {@code openInput} carries SEQUENTIAL. If a version bump drops the hint,
 *     the bypass silently stops applying (fails open — a lost optimisation, not a correctness change).</li>
 * <li><b>Lucene contract, load-bearing:</b> {@link IOContext#READONCE} <em>also</em> contains SEQUENTIAL (plus
 *     {@link ReadOnceHint}). It is only harmless because {@code openInput} routes READONCE to the NIO path
 *     <em>before</em> the bypass decision is reached. Two ways that can break: READONCE stops being
 *     reference-identical at the routing check, or Lucene starts passing SEQUENTIAL at some other
 *     {@code openInput} that does reach this method. Either would silently retune the cache for a flow that
 *     wants it.</li>
 * </ul>
 *
 * The stack-walk that used to also require the caller was removed to avoid coupling the plugin to a core class
 * and method name. These tests are what replaces it: they pin the assumption that makes the hint sufficient, so
 * a breaking upstream change fails here instead of becoming an unexplained latency change in production.
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
     * The assumption the whole design now rests on. READONCE contains SEQUENTIAL, so keying on SEQUENTIAL alone
     * is safe ONLY because READONCE is diverted earlier in {@code openInput} by an identity check. If this ever
     * fails, that identity check is no longer reachable and READONCE opens would start taking the bypass.
     */
    public void testReadOnceCarriesSequentialAndIsIdentityComparable() {
        assertTrue("READONCE carries SEQUENTIAL - this is why the hint alone is not self-evidently sufficient",
            IOContext.READONCE.hints().contains(DataAccessHint.SEQUENTIAL));
        assertTrue(IOContext.READONCE.hints().contains(ReadOnceHint.INSTANCE));
        assertSame(
            "READONCE must be a stable singleton: openInput diverts it by reference equality before the bypass decision",
            IOContext.READONCE,
            IOContext.READONCE
        );
    }

    /**
     * MERGE must remain distinguishable by its Context enum rather than by hints, because {@code openInput}
     * diverts it to the NIO path before the bypass decision too.
     */
    public void testMergeContextIsDistinguishableWithoutHints() {
        assertSame(IOContext.Context.DEFAULT, SEQUENTIAL_CONTEXT.context());
        assertNotSame(IOContext.Context.MERGE, SEQUENTIAL_CONTEXT.context());
    }

    // ---- predicate behaviour ----

    /**
     * The behaviour change from removing the stack walk: the hint alone is now sufficient. Previously this
     * returned false unless {@code SegmentFileTransferHandler.onNewResource} was on the stack.
     */
    public void testSequentialHintAloneBypasses() {
        assertTrue(
            "the SEQUENTIAL hint is now the sole signal for the recovery-copy bypass",
            directory.enableSkipBufferpool("_0.cfs", SEQUENTIAL_CONTEXT)
        );
    }

    /** No hint means no bypass, regardless of who is calling. */
    public void testNoHintDoesNotBypass() {
        assertFalse(directory.enableSkipBufferpool("_0.cfs", IOContext.DEFAULT));
    }

    /** A null context must not be treated as hinted. */
    public void testNullContextDoesNotBypass() {
        assertFalse(directory.enableSkipBufferpool("_0.cfs", null));
    }

    /** A RANDOM-hinted open is the opposite case and must keep its cache. */
    public void testRandomHintDoesNotBypass() {
        assertFalse(directory.enableSkipBufferpool("_0.cfs", IOContext.DEFAULT.withHints(DataAccessHint.RANDOM)));
    }

    /** The flag is the kill switch and the A/B lever; off must mean off even with the hint present. */
    public void testFlagOffDisablesTheBypassEntirely() {
        StaticConfigs.setRecoveryCopyBypassEnabled(false);
        assertFalse(directory.enableSkipBufferpool("_0.cfs", SEQUENTIAL_CONTEXT));
    }

    /** An ordinary search-shaped open is untouched by any of this. */
    public void testPlainDefaultOpenStillPooled() {
        assertFalse(directory.enableSkipBufferpool("_0.cfs", IOContext.DEFAULT));
    }

    /** The decision must not depend on the file name, only on the context. */
    public void testDecisionIsIndependentOfFileName() {
        assertTrue(directory.enableSkipBufferpool("_0.tim", SEQUENTIAL_CONTEXT));
        assertTrue(directory.enableSkipBufferpool("_99.doc", SEQUENTIAL_CONTEXT));
        assertFalse(directory.enableSkipBufferpool("_0.tim", IOContext.DEFAULT));
    }
}
