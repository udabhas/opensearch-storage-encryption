/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.indices.replication;

import java.util.concurrent.Callable;

/**
 * Test double that puts a frame on the stack matching the real recovery/segment-replication file-copy caller,
 * so the plugin's caller detection can be exercised through the <em>real</em> {@code StackWalker} instead of a
 * reimplementation of its matching rule.
 *
 * <h2>Why it lives in this package and is named like this</h2>
 * The plugin matches the enclosing class by prefix, {@code org.opensearch.indices.replication.SegmentFileTransferHandler},
 * because the copy's {@code openInput} happens inside an anonymous subclass ({@code ...$1}) whose synthetic name
 * is not part of any upstream contract. So the package and the class-name prefix here must match the real thing
 * for the detection to fire, and the method must be named {@code onNewResource}.
 *
 * <p>Deliberately <b>not</b> named exactly {@code SegmentFileTransferHandler}: an identically-named class in the
 * same package would shadow the real OpenSearch class on the test classpath and could change the behaviour of
 * unrelated tests. The {@code Double} suffix keeps the prefix match while leaving the real class reachable — and
 * it doubles as proof that the prefix match is intentionally loose enough to survive the {@code $1} suffix.
 */
public final class SegmentFileTransferHandlerCallerDouble {

    private SegmentFileTransferHandlerCallerDouble() {}

    /**
     * Invokes {@code body} with a frame named {@code onNewResource} on the stack, mimicking the real copy's
     * call into {@code Directory#openInput}.
     */
    public static <T> T onNewResource(Callable<T> body) throws Exception {
        return body.call();
    }
}
