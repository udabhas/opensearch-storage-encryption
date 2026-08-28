/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import org.opensearch.index.store.bufferpoolfs.ThreadKinds.ThreadKind;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Asserts the thread-name contract that {@link ThreadKinds} depends on.
 *
 * <p>These are not cosmetic. The classification decides whether a derivation may bypass the bufferpool, the
 * flag is inherited by every clone and slice, and a wrongly-flagged segment-core input stays wrong for the
 * lifetime of the segment. The negative cases are therefore the point of this class: thread names embed
 * customer-controlled index names, so the matcher has to be unforgeable rather than merely usually right.
 */
public class ThreadKindsTests extends OpenSearchTestCase {

    public void testPoolThreadsAreClassified() {
        assertEquals(ThreadKind.SNAPSHOT, ThreadKinds.classify("opensearch[node_t0][snapshot][T#1]"));
        assertEquals(ThreadKind.SNAPSHOT, ThreadKinds.classify("opensearch[node_t0][snapshot][T#5]"));
        assertEquals(ThreadKind.MERGE, ThreadKinds.classify("opensearch[node_t0][force_merge][T#1]"));
        assertEquals(ThreadKind.SEARCH, ThreadKinds.classify("opensearch[node_t0][search][T#3]"));
        assertEquals(ThreadKind.WARMER, ThreadKinds.classify("opensearch[node_t0][warmer][T#2]"));
    }

    /** A shard merge thread is named after the shard, not a pool, so it needs its own rule. */
    public void testShardMergeThreadIsMerge() {
        assertEquals(ThreadKind.MERGE, ThreadKinds.classify("opensearch[node_t0][[big5][0]: Lucene Merge Thread #0]"));
        assertEquals(ThreadKind.MERGE, ThreadKinds.classify("opensearch[node_t0][[snap-flow][12]: Lucene Merge Thread #3]"));
    }

    /**
     * The load-bearing negatives. Shard-scoped thread names embed the INDEX NAME, and index names are
     * customer-controlled — so a match on {@code "snapshot"}, or even on {@code "[snapshot]"}, is forgeable.
     * Only {@code "[snapshot][T#"} is not, because {@code [T#} follows a POOL name and nothing else.
     */
    public void testIndexNamesCannotForgeAPoolMatch() {
        // would match a naive contains("snapshot")
        assertEquals(ThreadKind.MERGE, ThreadKinds.classify("opensearch[n][[snapshot-backups][0]: Lucene Merge Thread #0]"));
        assertEquals(ThreadKind.MERGE, ThreadKinds.classify("opensearch[n][[daily-snapshots][2]: Lucene Merge Thread #1]"));
        // would match a naive contains("[snapshot]") - index named EXACTLY "snapshot"
        assertEquals(ThreadKind.MERGE, ThreadKinds.classify("opensearch[n][[snapshot][0]: Lucene Merge Thread #0]"));
        // an index named "search" must not be mistaken for the search pool
        assertEquals(ThreadKind.MERGE, ThreadKinds.classify("opensearch[n][[search][0]: Lucene Merge Thread #0]"));
        // a refresh thread for an index named "snapshot" is neither SNAPSHOT nor MERGE
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("opensearch[n][refresh][T#1]"));
    }

    /** The sibling snapshot pools are different pools and must not be treated as the upload pool. */
    public void testSiblingSnapshotPoolsAreNotSnapshot() {
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("opensearch[node_t0][snapshot_deletion][T#1]"));
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("opensearch[node_t0][snapshot_shards][T#1]"));
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("opensearch[node_t0][snapshot_segments][T#1]"));
    }

    public void testEverythingElseIsOther() {
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("opensearch[node_t0][generic][T#4]"));
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("opensearch[node_t0][write][T#1]"));
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("opensearch[node_t0][flush][T#1]"));
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify("main"));
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify(""));
        assertEquals(ThreadKind.OTHER, ThreadKinds.classify(null));
    }

    /**
     * The gate must skip the stack walk only where a field data build is PROVABLY impossible. An allowlist of
     * eligible pools ({@code SEARCH || WARMER}) was tried first and was wrong: field data can be loaded by any
     * caller that touches a field, so an allowlist fails silently on paths nobody enumerated. Anything not
     * proven impossible - including OTHER, i.e. threads we have not classified - must still walk.
     */
    public void testWalkIsSkippedOnlyWhereABuildIsImpossible() {
        assertTrue(ThreadKinds.provablyNotFieldDataBuild(ThreadKind.SNAPSHOT));
        assertTrue(ThreadKinds.provablyNotFieldDataBuild(ThreadKind.MERGE));
        assertFalse(ThreadKinds.provablyNotFieldDataBuild(ThreadKind.SEARCH));
        assertFalse(ThreadKinds.provablyNotFieldDataBuild(ThreadKind.WARMER));
        assertFalse(
            "an unclassified thread must still be walked, not silently skipped",
            ThreadKinds.provablyNotFieldDataBuild(ThreadKind.OTHER)
        );
    }

    /** The cached per-thread lookup must agree with a direct classification of that thread's name. */
    public void testCachedCurrentAgreesWithClassify() throws Exception {
        final ThreadKind[] seen = new ThreadKind[1];
        Thread t = new Thread(() -> {
            seen[0] = ThreadKinds.current();
            // second call comes from the ThreadLocal cache and must not differ
            assertEquals(seen[0], ThreadKinds.current());
        }, "opensearch[node_t0][snapshot][T#1]");
        t.start();
        t.join();
        assertEquals(ThreadKind.SNAPSHOT, seen[0]);
    }
}
