/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import java.nio.file.Path;

import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.NoLockFactory;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.CryptoTestDirectoryFactory;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Tests the create-time bypass decision in {@link BufferPoolDirectory#enableSkipBufferpool(String, IOContext)}.
 *
 * <p>The predicate keys on the thread pool, because the snapshot upload opens with
 * {@code IOContext.DEFAULT} and an empty hint set — byte-for-byte identical to a search open — so the
 * IOContext carries no usable signal. That makes the exact form of the thread-name match the load-bearing
 * detail, and the negative cases below are the point of this class rather than an afterthought: a false
 * positive sets the flag on a segment-lifetime input, and {@code buildSlice} propagates it to every clone,
 * so the mistake persists for as long as the segment does.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class SkipBufferpoolRoutingTests extends OpenSearchTestCase {

    private BufferPoolDirectory directory;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        // The global A/B switch is consulted first by the predicate, so it must be off or every case
        // below trivially returns true.
        StaticConfigs.setBlockCacheBypassEnabled(false);
        Path path = createTempDir();
        directory = CryptoTestDirectoryFactory.createBufferPoolDirectory(path, NoLockFactory.INSTANCE);
    }

    @Override
    public void tearDown() throws Exception {
        StaticConfigs.setBlockCacheBypassEnabled(false);
        if (directory != null) {
            directory.close();
        }
        super.tearDown();
    }

    /**
     * Runs the predicate on a thread with a controlled name, so it is exercised through the real method
     * rather than a reimplementation of the matching rule.
     */
    private boolean decideOnThreadNamed(String threadName) throws Exception {
        final boolean[] result = new boolean[1];
        final Exception[] failure = new Exception[1];
        Thread t = new Thread(() -> {
            try {
                result[0] = directory.enableSkipBufferpool("_0.cfs", IOContext.DEFAULT);
            } catch (Exception e) {
                failure[0] = e;
            }
        }, threadName);
        t.start();
        t.join();
        if (failure[0] != null) {
            throw failure[0];
        }
        return result[0];
    }

    /** A real snapshot-pool thread is the one case that must bypass. */
    public void testSnapshotPoolThreadEnablesSkipBufferpool() throws Exception {
        assertTrue(decideOnThreadNamed("opensearch[node_t0][snapshot][T#1]"));
        // The pool is SCALING with max 5, so every worker index must match, not just T#1.
        assertTrue(decideOnThreadNamed("opensearch[node_t0][snapshot][T#5]"));
    }

    /**
     * The load-bearing negative case, and the reason the predicate matches {@code "[snapshot][T#"} rather
     * than {@code "snapshot"}.
     *
     * <p>Shard-scoped thread names embed the INDEX NAME. A customer index called {@code snapshot-backups}
     * produces a merge thread named {@code opensearch[node][[snapshot-backups][0]: Lucene Merge Thread #0]},
     * and merge threads DO reach this branch — to build {@code SegmentCoreReaders} inputs, which are
     * segment-lifetime. Index names are customer-controlled, so a loose match turns an index name into a
     * silent, long-lived cache bypass on that index's search reads.
     */
    public void testIndexNamesContainingSnapshotDoNotEnableSkipBufferpool() throws Exception {
        assertFalse(decideOnThreadNamed("opensearch[node_t0][[snapshot-backups][0]: Lucene Merge Thread #0]"));
        assertFalse(decideOnThreadNamed("opensearch[node_t0][[daily-snapshots][2]: Lucene Merge Thread #1]"));
        // The nastiest one: an index named EXACTLY "snapshot" yields the substring "[snapshot]", which a
        // bracket-only match would wrongly accept.
        assertFalse(decideOnThreadNamed("opensearch[node_t0][[snapshot][0]: Lucene Merge Thread #0]"));
    }

    /** The sibling snapshot pools must not match: none of them stream shard files through this branch. */
    public void testSiblingSnapshotPoolsDoNotEnableSkipBufferpool() throws Exception {
        assertFalse(decideOnThreadNamed("opensearch[node_t0][snapshot_deletion][T#1]"));
        assertFalse(decideOnThreadNamed("opensearch[node_t0][snapshot_shards][T#1]"));
        assertFalse(decideOnThreadNamed("opensearch[node_t0][snapshot_segments][T#1]"));
    }

    /** Every other pool keeps the pooled + cached path. */
    public void testUnrelatedPoolsDoNotEnableSkipBufferpool() throws Exception {
        assertFalse(decideOnThreadNamed("opensearch[node_t0][search][T#3]"));
        assertFalse(decideOnThreadNamed("opensearch[node_t0][force_merge][T#1]"));
        assertFalse(decideOnThreadNamed("opensearch[node_t0][refresh][T#1]"));
        assertFalse(decideOnThreadNamed("opensearch[node_t0][generic][T#4]"));
        assertFalse(decideOnThreadNamed("opensearch[node_t0][write][T#1]"));
    }

    /** The global A/B switch still short-circuits everything, so a whole run can be compared. */
    public void testGlobalBypassSwitchOverridesTheThreadCheck() throws Exception {
        StaticConfigs.setBlockCacheBypassEnabled(true);
        try {
            assertTrue(decideOnThreadNamed("opensearch[node_t0][search][T#3]"));
        } finally {
            StaticConfigs.setBlockCacheBypassEnabled(false);
        }
    }
}
