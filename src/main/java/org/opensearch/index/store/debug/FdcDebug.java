/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.debug;

import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.IOContext;

/**
 * Throwaway read-path tracing helper (Track 17). Not a production facility.
 *
 * <p>Answers one question: <em>who reads what, through which route, and does the block cache get
 * populated as a side effect?</em> Every line is tagged {@code fdc-debug} so a whole run can be
 * extracted with a single grep.
 *
 * <h2>Why call-site identity and not a stack dump per event</h2>
 * A stack walk costs microseconds; a block load costs ~1&nbsp;ms but happens millions of times per
 * benchmark. So the chain is walked, hashed, and emitted <strong>once per distinct call path</strong>;
 * every subsequent event on that path carries only the hash. A recovery that opens ~10k files
 * produces ~10k short lines and a handful of chains, not 10k stack dumps.
 *
 * <h2>Two tiers, deliberately different</h2>
 * <ul>
 * <li>{@link #site} — <strong>lifecycle</strong> sites: {@code openInput}, {@code createOutput},
 *     {@code clone}, {@code slice}, {@code close}. Measured at ~10.4k opens per recovery and zero
 *     while idle, so walking here is affordable.</li>
 * <li>{@link #hotSite} — <strong>per-block</strong> sites: block acquire and the block loader. These
 *     run on the query hot path (a clone per TermsEnum, a clone per DocsEnum), so the walk is
 *     <em>off</em> by default and the log line is emitted only once per distinct call path. Turn the
 *     walk on with {@code -Dopensearch.store.fdcdebug.hotstacks=true} for a short diagnostic run
 *     only — never while timing anything.</li>
 * </ul>
 *
 * <h2>IOContext decoding</h2>
 * {@link #describe(IOContext)} prints the hint set <em>and</em> resolves read-once by hint type
 * rather than by the {@code INSTANCE} constant, because {@code ReadOnceHint.INSTANCE} and
 * {@code PreloadHint.INSTANCE} render identically in a hint set, which makes them easy to
 * misread as each other. It also prints whether reference equality against {@code IOContext.READONCE} agrees with
 * the hint-based answer, which is exactly the discrepancy that routing bugs hide behind.
 *
 * @opensearch.internal
 */
public final class FdcDebug {

    private FdcDebug() {}

    /** Force tracing on even when the logger is not at DEBUG. */
    private static final String PROP_FORCE = "opensearch.store.fdcdebug";
    /** Walk stacks at lifecycle sites. Default true; set false for log lines with no chains. */
    private static final String PROP_STACKS = "opensearch.store.fdcdebug.stacks";
    /** Walk stacks at per-block hot sites. Default FALSE. See class docs before enabling. */
    private static final String PROP_HOT_STACKS = "opensearch.store.fdcdebug.hotstacks";
    /** Max OpenSearch/Lucene frames retained per chain. */
    private static final String PROP_FRAMES = "opensearch.store.fdcdebug.frames";
    /**
     * Emit node-global buffer-pool state inline at every derivation ({@code clone} / {@code slice}).
     * Default FALSE - it builds three stats strings per call, so it is for small confirmatory runs only.
     */
    private static final String PROP_POOL_STATE = "opensearch.store.fdcdebug.poolstate";

    /** Exhaustive reflective dump of the calling thread's ThreadLocals. Diagnostic only; see {@link #threadLocalsDump()}. */
    private static final String PROP_THREAD_LOCALS = "opensearch.store.fdcdebug.threadlocals";

    /**
     * Logs the derive-side marker decision for BOTH outcomes, deduped per thread, so a diagnostic run can
     * see that an ordinary search reaches the hook and reads {@code false}. Off by default: without the
     * dedupe this would be one line per derivation on the query hot path.
     */
    private static final String PROP_MARKER_PROBE = "opensearch.store.fdcdebug.markerprobe";

    private static final boolean FORCE = Boolean.parseBoolean(System.getProperty(PROP_FORCE, "false"));
    private static final boolean STACKS = Boolean.parseBoolean(System.getProperty(PROP_STACKS, "true"));
    private static final boolean HOT_STACKS = Boolean.parseBoolean(System.getProperty(PROP_HOT_STACKS, "false"));
    private static final int MAX_FRAMES = Integer.parseInt(System.getProperty(PROP_FRAMES, "24"));
    private static final boolean POOL_STATE = Boolean.parseBoolean(System.getProperty(PROP_POOL_STATE, "false"));
    private static final boolean THREAD_LOCALS = Boolean.parseBoolean(System.getProperty(PROP_THREAD_LOCALS, "false"));
    private static final boolean MARKER_PROBE = Boolean.parseBoolean(System.getProperty(PROP_MARKER_PROBE, "false"));

    /** Call-site hashes already emitted with a full chain. Bounded by the number of distinct paths. */
    private static final Set<Integer> SEEN = ConcurrentHashMap.newKeySet();

    /** Frames from this helper are not caller information. */
    private static final String SELF_PACKAGE = "org.opensearch.index.store.debug";

    /**
     * Per-site event counts, so a flow claim can be ASSERTED instead of eyeballed in a log.
     *
     * <p>This exists because the interesting facts about the read path are negative ones - "the
     * fielddata build performs zero {@code openInput} calls and reaches the disk only through clones of
     * inputs opened earlier" - and a negative is exactly what grepping a log establishes least reliably.
     * A missing line is indistinguishable from a logger that was never enabled. A counter delta of zero,
     * taken across an operation whose other counters moved, is real evidence.
     *
     * <p>Only maintained while tracing is on, so there is no cost on a production read path.
     */
    private static final ConcurrentHashMap<String, LongAdder> COUNTERS = new ConcurrentHashMap<>();

    /**
     * True once any traced code path has been observed, so {@link #count} can no-op cheaply when tracing is
     * off. Latched rather than re-derived because {@code count} has no {@link Logger} to consult, and adding
     * one to every call site would push the check to places (the block cache) that have no business knowing
     * about tracing.
     */
    private static final Set<Long> PROBE_SEEN = ConcurrentHashMap.newKeySet();

    private static volatile boolean counting = FORCE;

    /**
     * Increments the event count for a site.
     *
     * <p>Early-returns when nothing has enabled tracing, because several call sites are on the per-block
     * read path where an unconditional map lookup plus {@link LongAdder} increment would be real production
     * cost for a value nobody reads. Call sites that BUILD their key by concatenation must still gate on
     * {@link #on} themselves - the string is allocated before this method is entered, so an early return
     * here cannot save it.
     */
    /**
     * Turns counting on without turning tracing on. For an experiment that emits its own log lines and
     * wants the totals too, but does not want the whole {@code fdc-debug} stream.
     */
    public static void enableCounting() {
        counting = true;
    }

    public static void count(String site) {
        if (counting == false) {
            return;
        }
        COUNTERS.computeIfAbsent(site, k -> new LongAdder()).increment();
    }

    /** Immutable ordered snapshot of all site counts. */
    public static Map<String, Long> counters() {
        Map<String, Long> out = new TreeMap<>();
        COUNTERS.forEach((k, v) -> out.put(k, v.sum()));
        return out;
    }

    /** Count for one site, 0 if never seen. */
    public static long counterOf(String site) {
        LongAdder a = COUNTERS.get(site);
        return a == null ? 0L : a.sum();
    }

    /** Clears all counts. Call immediately before the operation under measurement. */
    public static void resetCounters() {
        COUNTERS.clear();
    }

    /** Cheap gate. Callers must wrap every trace call in this. */
    public static boolean on(Logger log) {
        if (FORCE) {
            return true;
        }
        if (log.isDebugEnabled()) {
            counting = true;
            return true;
        }
        return false;
    }

    /**
     * Emits one trace line. At INFO when tracing was explicitly forced via
     * {@code -Dopensearch.store.fdcdebug=true}, otherwise at DEBUG.
     *
     * <p>The level switch is the point. Gating on {@link #on} alone is not enough: a forced flag makes
     * the gate true while {@code logger.debug(..)} still drops the line unless the package logger has
     * also been widened to DEBUG — which drags in every other DEBUG statement in the store packages.
     * Forcing means "I asked for exactly this", so it emits at INFO and stays targeted. Unconditional
     * INFO tracing floods a busy node, which is why this is opt-in only.
     */
    public static void log(Logger log, String format, Object... args) {
        if (FORCE) {
            log.info(format, args);
        } else {
            log.debug(format, args);
        }
    }

    /**
     * Buffer-pool state for inline emission at a derivation, or {@code ""} when disabled.
     *
     * <p>Answers "did the pool move across THIS clone?" rather than "what did the pool look like at some
     * point in the last ten seconds", which is all the background telemetry thread can say - it sleeps 10s
     * between records and a whole field data build plus the query phase that follows it fit inside 122ms,
     * so a tick cannot attribute anything at this granularity.
     *
     * <p>Reflectively decoupled from {@code CryptoDirectoryFactory} on purpose: this helper lives in the
     * debug package and must not create a compile-time dependency from the tracing layer onto the factory
     * that owns the pool. Reflection cost is irrelevant because the whole thing is off by default and only
     * used in small confirmatory runs.
     */
    public static String poolState() {
        if (POOL_STATE == false) {
            return "";
        }
        try {
            Class<?> factory = Class.forName("org.opensearch.index.store.CryptoDirectoryFactory");
            Object snapshot = factory.getMethod("poolStateSnapshot").invoke(null);
            return " pool={" + snapshot + "}";
        } catch (ReflectiveOperationException | RuntimeException e) {
            return " pool={unavailable:" + e.getClass().getSimpleName() + "}";
        }
    }

    /** Current thread name, for flow attribution (merge / snapshot / generic / warmer / search). */
    public static String thread() {
        return Thread.currentThread().getName();
    }

    /**
     * Lifecycle call site. Walks and hashes the caller chain, emitting the full chain the first time
     * that path is seen. Returns the hash to correlate later lines on the same path.
     *
     * @param log   logger of the calling class
     * @param tag   short site name, e.g. {@code "hybrid.openInput"}
     * @param what  the subject (file name, path)
     * @return the call-site hash, or 0 when stack walking is disabled
     */
    public static int site(Logger log, String tag, Object what) {
        return record(log, tag, what, STACKS);
    }

    /**
     * Per-block hot call site. Emits at most one line per distinct call path and does not walk the
     * stack unless {@code -Dopensearch.store.fdcdebug.hotstacks=true}.
     *
     * @return the call-site hash, or 0 when hot-path stack walking is disabled
     */
    public static int hotSite(Logger log, String tag, Object what) {
        if (HOT_STACKS == false) {
            return 0;
        }
        return record(log, tag, what, true);
    }

    private static int record(Logger log, String tag, Object what, boolean walk) {
        if (walk == false) {
            return 0;
        }
        String chain = chain(MAX_FRAMES);
        int hash = chain.hashCode();
        if (SEEN.add(hash)) {
            log(log, "fdc-debug callsite NEW tag={} hash={} what={} thread={} chain={}", tag, hash, what, thread(), chain);
        }
        return hash;
    }

    /**
     * One-line trace for a Directory operation that carries no {@link IOContext}
     * ({@code listAll}, {@code sync}, {@code rename}, {@code deleteFile}, {@code fileLength}, ...).
     *
     * <p>Gate-checks internally so call sites stay a single statement. The gate is a flag read plus a
     * logger level check, which is affordable on lifecycle paths but NOT on per-block paths.
     */
    public static void dirOp(Logger log, String site, String detail) {
        if (on(log) == false) {
            return;
        }
        count(site);
        int callsite = site(log, site, detail);
        log(log, "fdc-debug {} {} thread={} callsite={}", site, detail, thread(), callsite);
    }

    /** One-line trace for a Directory operation that carries an {@link IOContext}. */
    public static void dirOp(Logger log, String site, String detail, IOContext context) {
        if (on(log) == false) {
            return;
        }
        count(site);
        int callsite = site(log, site, detail);
        log(log, "fdc-debug {} {} {} thread={} callsite={}", site, detail, describe(context), thread(), callsite);
    }

    /** One-line trace recording the RESULT of an operation, e.g. a computed length or a route taken. */
    public static void dirResult(Logger log, String site, String detail, Object result) {
        if (on(log) == false) {
            return;
        }
        count(site);
        int callsite = site(log, site, detail);
        log(log, "fdc-debug {} {} result={} thread={} callsite={}", site, detail, result, thread(), callsite);
    }

    /**
     * OpenSearch/Lucene frames only, capped, with two cleanups that matter for call-site identity:
     *
     * <ul>
     * <li><b>Self-frames dropped.</b> The three {@code FdcDebug} frames are not caller information.</li>
     * <li><b>Consecutive duplicates collapsed.</b> {@code FilterDirectory.openInput} appears five times
     *     in a row on a wrapped store; left in, those five plus the self-frames consume 8 of 24 frames
     *     and push the actual caller ({@code FieldsIndexWriter.finish}) to the edge of the cap.
     *     Truncating the distinguishing frames is how two different callers end up sharing one
     *     call-site hash — which would silently merge two flows in the inventory.</li>
     * </ul>
     *
     * Frames past the cap are never materialised.
     */
    public static String chain(int maxFrames) {
        StringBuilder sb = new StringBuilder(256);
        StackWalker.getInstance().walk(frames -> {
            final String[] previous = new String[1];
            final int[] repeats = new int[1];
            frames
                .filter(f -> f.getClassName().startsWith("org.opensearch") || f.getClassName().startsWith("org.apache.lucene"))
                .filter(f -> f.getClassName().startsWith(SELF_PACKAGE) == false)
                .map(f -> f.getClassName() + '.' + f.getMethodName() + ':' + f.getLineNumber())
                .filter(frame -> {
                    if (frame.equals(previous[0])) {
                        repeats[0]++;
                        return false;
                    }
                    if (repeats[0] > 0) {
                        sb.append('x').append(repeats[0] + 1).append(' ');
                        repeats[0] = 0;
                    }
                    previous[0] = frame;
                    return true;
                })
                .limit(maxFrames)
                .forEach(frame -> sb.append(frame).append(" <- "));
            if (repeats[0] > 0) {
                sb.append('x').append(repeats[0] + 1).append(' ');
            }
            return null;
        });
        return sb.toString();
    }

    /**
     * Compact, unambiguous rendering of an {@link IOContext}.
     *
     * <p>Format: {@code ctx=DEFAULT hints=[SEQUENTIAL,INSTANCE] readOnce=true refEqReadOnce=true merge=false flush=false}
     *
     * <p>{@code readOnce} is resolved by hint <em>type</em>; {@code refEqReadOnce} is the reference
     * comparison that routing code has historically used. When these two disagree, routing that keys
     * on reference equality is silently missing a read-once open.
     */
    public static String describe(IOContext context) {
        if (context == null) {
            return "ctx=null";
        }
        boolean readOnce = false;
        StringBuilder hints = new StringBuilder(48);
        try {
            for (Object h : context.hints()) {
                if (hints.length() > 0) {
                    hints.append(',');
                }
                String simple = h.getClass().getSimpleName();
                // Enum constants render as INSTANCE/SEQUENTIAL/RANDOM; prefix with the hint type so
                // ReadOnceHint.INSTANCE and PreloadHint.INSTANCE are never confused for each other.
                hints.append(simple).append('.').append(h);
                if ("ReadOnceHint".equals(simple)) {
                    readOnce = true;
                }
            }
        } catch (Exception e) {
            hints.append("<unavailable:").append(e.getClass().getSimpleName()).append('>');
        }
        return "ctx="
            + context.context()
            + " hints=["
            + hints
            + "] readOnce="
            + readOnce
            + " refEqReadOnce="
            + (context == IOContext.READONCE)
            + " merge="
            + (context.mergeInfo() != null)
            + " flush="
            + (context.flushInfo() != null);
    }

    /** Clears the emitted-call-site set so a fresh run re-emits every chain. Test/diagnostic use. */
    public static void resetCallsites() {
        SEEN.clear();
        PROBE_SEEN.clear();
    }

    /**
     * Exhaustive dump of EVERY {@code ThreadLocal} on the calling thread, both the ordinary and the
     * inheritable map, by reflecting into {@code Thread.threadLocals}.
     *
     * <p>Diagnostic only, and OFF by default. Enable with
     * {@code -Dopensearch.store.fdcdebug.threadlocals=true}, which also requires
     * {@code --add-opens java.base/java.lang=ALL-UNNAMED} on the JVM - without it the reflective access
     * throws and this returns the reason rather than failing the caller.
     *
     * <p>Deliberately not used for assertions anywhere. The output is dominated by entries that have
     * nothing to do with this code - Lucene codec scratch, Netty buffers, randomized-testing seeds,
     * MessageDigests, DeflateCompressor - so it is useful for answering "what else is on this thread"
     * during an investigation and useless as a proof. The targeted state is logged by the caller instead.
     *
     * @return one {@code key=value} entry per line, or a single line explaining why it could not be read
     */
    public static String threadLocalsDump() {
        if (THREAD_LOCALS == false) {
            return "disabled (set -D" + PROP_THREAD_LOCALS + "=true)";
        }
        StringBuilder sb = new StringBuilder(512);
        final Thread thread = Thread.currentThread();
        sb.append("tid=").append(thread.threadId()).append(" name=").append(thread.getName());
        int total = 0;
        for (String field : new String[] { "threadLocals", "inheritableThreadLocals" }) {
            try {
                java.lang.reflect.Field mapField = Thread.class.getDeclaredField(field);
                mapField.setAccessible(true);
                Object map = mapField.get(thread);
                if (map == null) {
                    sb.append("\n  ").append(field).append(": (none)");
                    continue;
                }
                java.lang.reflect.Field tableField = map.getClass().getDeclaredField("table");
                tableField.setAccessible(true);
                Object[] table = (Object[]) tableField.get(map);
                sb.append("\n  ").append(field).append(": slots=").append(table == null ? 0 : table.length);
                if (table == null) {
                    continue;
                }
                java.lang.reflect.Field valueField = null;
                for (Object entry : table) {
                    if (entry == null) {
                        continue;
                    }
                    if (valueField == null) {
                        valueField = entry.getClass().getDeclaredField("value");
                        valueField.setAccessible(true);
                    }
                    Object key = ((java.lang.ref.Reference<?>) entry).get();
                    Object value = valueField.get(entry);
                    total++;
                    sb
                        .append("\n    [")
                        .append(total)
                        .append("] key=")
                        .append(key == null ? "<cleared weak ref>" : key.getClass().getName())
                        .append(" value=")
                        .append(describeValue(value));
                }
            } catch (RuntimeException | ReflectiveOperationException e) {
                // InaccessibleObjectException without --add-opens; report it rather than throwing, so a
                // missing JVM flag degrades this diagnostic instead of failing the operation being traced.
                sb
                    .append("\n  ")
                    .append(field)
                    .append(": UNREADABLE (")
                    .append(e.getClass().getSimpleName())
                    .append(": ")
                    .append(e.getMessage())
                    .append(")");
            }
        }
        return sb.append("\n  entries=").append(total).toString();
    }

    /** Type plus a bounded rendering: a ThreadLocal value can be a huge buffer, and toString may be costly. */
    private static String describeValue(Object value) {
        if (value == null) {
            return "null";
        }
        String type = value.getClass().getName();
        if (value instanceof byte[] a) {
            return type + "(len=" + a.length + ")";
        }
        if (value instanceof Object[] a) {
            return type + "(len=" + a.length + ")";
        }
        if (value instanceof Boolean || value instanceof Number || value instanceof CharSequence) {
            String text = String.valueOf(value);
            return type + "(" + (text.length() > 60 ? text.substring(0, 60) + "..." : text) + ")";
        }
        return type;
    }

    /** Whether the marker probe is enabled at all. See {@code opensearch.store.fdcdebug.markerprobe}. */
    public static boolean markerProbe() {
        return MARKER_PROBE;
    }

    /**
     * True once per thread per {@link #resetCallsites()} window, so the probe can log a per-derivation
     * decision without emitting a line for every derivation on the query hot path.
     */
    public static boolean probeOnce() {
        return MARKER_PROBE && PROBE_SEEN.add(Thread.currentThread().threadId());
    }

}
