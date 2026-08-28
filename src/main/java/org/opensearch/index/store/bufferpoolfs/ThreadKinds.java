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
     * True on a thread where a field data build can occur, and therefore the only case where walking the
     * stack to look for one can succeed.
     *
     * <p>{@code SEARCH} covers the on-demand build during aggregator construction. {@code WARMER} is included
     * deliberately: {@code eager} / {@code eager_global_ordinals} field data is built by the index warmer on
     * the {@code warmer} pool, so gating on {@code SEARCH} alone would produce silent false negatives — the
     * build would not be detected and would quietly keep polluting the pool.
     */
    static boolean canHostFieldDataBuild(ThreadKind kind) {
        return kind == ThreadKind.SEARCH || kind == ThreadKind.WARMER;
    }
}
