/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

/**
 * Classifies the calling thread by the OpenSearch thread pool it belongs to, once per thread.
 *
 * <p>Exists because the bypass decision is consulted on paths that cannot afford to work for it: the
 * create-side hook runs per {@code openInput}, and the derive-side hook runs per {@code clone()} /
 * {@code slice()} — measured at 21,648 derived inputs in a single merge test. Recomputing a
 * {@code String.contains} over a ~40-character thread name at that rate is pure waste, because a thread's
 * name does not change: OpenSearch's {@code OpenSearchExecutors.daemonThreadFactory} assigns the name at
 * construction and no pool renames per task. So the classification is cached in a {@link ThreadLocal} and
 * every subsequent query is a field read.
 *
 * <p><b>If that assumption ever breaks</b> — some pool starts renaming threads per task — this cache goes
 * stale silently, which is the dangerous failure direction. {@link #classify(String)} is therefore package
 * -private and directly unit-tested, so the naming contract is asserted rather than assumed.
 *
 * @opensearch.internal
 */
final class ThreadKinds {

    private ThreadKinds() {}

    /** Which pool the calling thread belongs to, to the resolution the bypass decision needs. */
    enum ThreadKind {
        /** {@code snapshot} pool — snapshot upload reads. One-shot, never re-read. */
        SNAPSHOT,
        /** {@code force_merge} pool or a shard's Lucene merge thread. */
        MERGE,
        /** {@code search} pool — where a field data build happens, during aggregator construction. */
        SEARCH,
        /** {@code warmer} pool — where an eager / eager_global_ordinals field data build happens. */
        WARMER,
        /** Anything else: refresh, flush, generic, write, management, and every non-pool thread. */
        OTHER
    }

    /**
     * Cached per thread. A thread's name is fixed at construction, so this is computed once and then read.
     * One enum reference per thread, so the footprint is irrelevant.
     */
    private static final ThreadLocal<ThreadKind> CACHED = ThreadLocal.withInitial(() -> classify(Thread.currentThread().getName()));

    /** The calling thread's kind. A {@link ThreadLocal} read after the first call on that thread. */
    static ThreadKind current() {
        return CACHED.get();
    }

    /**
     * Maps a thread name to a {@link ThreadKind}.
     *
     * <p><b>Pool threads are matched as {@code "[<pool>][T#"}, never as the bare pool name.</b> Shard-scoped
     * thread names embed the INDEX NAME — {@code opensearch[node][[my-index][0]: Lucene Merge Thread #0]} —
     * so matching {@code "snapshot"} would fire on any index called {@code snapshot-backups}, and matching
     * {@code "[snapshot]"} would still fire on an index called exactly {@code snapshot}. {@code [T#} is
     * appended by the thread factory only after a POOL name, so it cannot be forged through an index name.
     * That precision is load-bearing: a false positive flags a segment-lifetime input, and the flag is
     * inherited by every clone, so the mistake would persist for as long as the segment does.
     *
     * <p>The merge case cannot use that form, because a shard merge thread is named
     * {@code [[index][shard]: Lucene Merge Thread #n]} rather than after a pool. Matching the literal
     * {@code "Lucene Merge Thread"} is nonetheless unforgeable: OpenSearch index names may not contain
     * spaces, so no index name can produce that substring.
     */
    static ThreadKind classify(String threadName) {
        if (threadName == null) {
            return ThreadKind.OTHER;
        }
        if (threadName.contains("[snapshot][T#")) {
            return ThreadKind.SNAPSHOT;
        }
        if (threadName.contains("[force_merge][T#") || threadName.contains("Lucene Merge Thread")) {
            return ThreadKind.MERGE;
        }
        if (threadName.contains("[search][T#")) {
            return ThreadKind.SEARCH;
        }
        if (threadName.contains("[warmer][T#")) {
            return ThreadKind.WARMER;
        }
        return ThreadKind.OTHER;
    }

    /**
     * True only when this thread provably CANNOT be running a field data build, so the caller may skip the
     * stack walk that would otherwise decide.
     *
     * <p><b>Deliberately a denylist, not an allowlist.</b> An earlier version asked the opposite question -
     * "can this thread host a build?" - and answered it with {@code SEARCH || WARMER}. That is a guess at
     * what is possible, and it is not enumerable: field data is loaded through
     * {@code IndicesFieldDataCache} and any caller that touches a field can trigger it. A wrong guess fails
     * SILENTLY - the build is not detected, the bypass does not apply, and nothing errors. It was caught only
     * because {@code testFieldDataBuildDerivationBypassesEvenWhenParentDoesNot} derives on the JUnit thread,
     * which the allowlist classified as ineligible.
     *
     * <p>So this asks the question that can actually be answered: is a field data build IMPOSSIBLE here?
     * A snapshot upload streams files to a repository and never uninverts anything; a Lucene merge thread
     * reads postings and doc values to merge them, never through {@code loadDirect}. Everything else -
     * including any thread we have not thought of - still pays for the walk and is therefore still correct.
     *
     * <p>This keeps the win that mattered: a merge test measured 21,648 derived inputs, and none of them now
     * walks the stack.
     */
    static boolean provablyNotFieldDataBuild(ThreadKind kind) {
        return kind == ThreadKind.SNAPSHOT || kind == ThreadKind.MERGE;
    }
}
