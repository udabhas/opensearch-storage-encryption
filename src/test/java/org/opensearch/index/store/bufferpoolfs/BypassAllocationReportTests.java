/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;

import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.store.NoLockFactory;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.CryptoTestDirectoryFactory;
import org.opensearch.index.store.debug.FdcDebug;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * A/B allocation report for the block-cache bypass ({@code skipBufferpool} -> {@code loadTransient}).
 *
 * <p>Not an assertion-heavy correctness test — it exists to produce comparable NUMBERS for the two
 * configurations over an identical workload, because the integ suite cannot: it runs the node's reads
 * on search threads (so per-thread allocation is unattributable) and its heavy classes OOM the test
 * JVM before finishing.
 *
 * <p>Everything runs on the test thread, so {@code getThreadAllocatedBytes(currentThread)} is exact.
 * Three deliberately redundant instruments, so they cross-check each other:
 * <ul>
 *   <li>{@code ThreadMXBean.getThreadAllocatedBytes} — measured HEAP bytes</li>
 *   <li>{@code BufferPoolMXBean("direct")} — measured DIRECT bytes and buffer count</li>
 *   <li>{@link FdcDebug} counters — attributable block counts; every block is exactly
 *       {@code CACHE_BLOCK_SIZE}, so bytes are derivable and should agree with the above</li>
 * </ul>
 *
 * <p>Both phases share ONE directory (hence one encryption key) and the measured pass is the WARM
 * one, so what is reported is steady-state per-block cost: the pooled path serving from L1/L2 versus
 * the bypass path re-reading every block. That is the production-relevant contrast.
 *
 * <p>The one assertion that matters: both paths must return byte-identical data. A bypass that is
 * cheap and wrong is worthless, and nothing else in the suite compares bypass output to cached output.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class BypassAllocationReportTests extends OpenSearchTestCase {

    private static final Logger LOGGER = LogManager.getLogger(BypassAllocationReportTests.class);

    /**
     * Sized to fit the test pool's segment budget. At 32 MiB (512 blocks) the POOLED phase exhausted
     * the pool (inUse=563 vs max=512) and fell back to degraded HEAP buffers, which inflated its heap
     * figure and made it a comparison against degraded mode rather than against normal pooled reads.
     */
    private static final int FILE_BYTES = 8 * 1024 * 1024;   // 8 MiB => 128 blocks of 64 KiB
    private static final int READ_BUF = 16 * 1024;

    private record Sample(long heapBytes, long directBytes, long directCount, Map<String, Long> counters, byte[] digest) {
    }

    public void testBypassVsPooledAllocationReport() throws Exception {
        CryptoTestDirectoryFactory.initMetrics();
        final boolean originalBypass = StaticConfigs.blockCacheBypassEnabled();

        try (Directory d = CryptoTestDirectoryFactory.createBufferPoolDirectory(createTempDir(), NoLockFactory.INSTANCE)) {
            writeFile(d);

            StaticConfigs.setBlockCacheBypassEnabled(false);
            final Sample pooled = measure(d, "POOLED");

            StaticConfigs.setBlockCacheBypassEnabled(true);
            final Sample bypass = measure(d, "BYPASS");

            assertArrayEquals("bypass must return byte-identical data to the pooled path", pooled.digest(), bypass.digest());

            report(pooled, bypass);
        } finally {
            StaticConfigs.setBlockCacheBypassEnabled(originalBypass);
        }
    }

    private void writeFile(Directory d) throws Exception {
        try (IndexOutput out = d.createOutput("data.bin", IOContext.DEFAULT)) {
            final byte[] chunk = new byte[READ_BUF];
            for (int i = 0; i < chunk.length; i++) {
                chunk[i] = (byte) (i * 31 + 7);
            }
            for (int written = 0; written < FILE_BYTES; written += chunk.length) {
                out.writeBytes(chunk, chunk.length);
            }
        }
    }

    /** Warm-up pass (JIT + footer/metadata cache), then a measured pass. */
    private Sample measure(Directory d, String label) throws Exception {
        readAll(d, MessageDigest.getInstance("SHA-256"));

        FdcDebug.resetCounters();
        System.gc();
        Thread.sleep(50);

        final long heap0 = allocatedBytes();
        final long direct0 = directBytes();
        final long dcount0 = directCount();

        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        readAll(d, md);

        final Sample s = new Sample(
            allocatedBytes() - heap0,
            directBytes() - direct0,
            directCount() - dcount0,
            FdcDebug.counters(),
            md.digest()
        );
        LOGGER.info("phase={} poolState={}", label, org.opensearch.index.store.CryptoDirectoryFactory.poolStateSnapshot());
        return s;
    }

    private void readAll(Directory d, MessageDigest md) throws Exception {
        try (IndexInput in = d.openInput("data.bin", IOContext.DEFAULT)) {
            final byte[] buf = new byte[READ_BUF];
            long remaining = in.length();
            while (remaining > 0) {
                final int n = (int) Math.min(buf.length, remaining);
                in.readBytes(buf, 0, n);
                md.update(buf, 0, n);
                remaining -= n;
            }
        }
    }

    private static long allocatedBytes() {
        final var mx = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        return mx.getThreadAllocatedBytes(Thread.currentThread().threadId());
    }

    private static BufferPoolMXBean directPool() {
        final List<BufferPoolMXBean> pools = ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class);
        for (BufferPoolMXBean p : pools) {
            if ("direct".equals(p.getName())) {
                return p;
            }
        }
        throw new IllegalStateException("no direct BufferPoolMXBean");
    }

    private static long directBytes() {
        return directPool().getMemoryUsed();
    }

    private static long directCount() {
        return directPool().getCount();
    }

    private void report(Sample pooled, Sample bypass) {
        final long blocks = FILE_BYTES / CACHE_BLOCK_SIZE;
        final StringBuilder sb = new StringBuilder(2048);
        sb.append(System.lineSeparator());
        sb.append("=============== BYPASS vs POOLED allocation report ===============").append(System.lineSeparator());
        sb
            .append(
                String
                    .format(
                        "workload: sequential read of %d MiB = %d blocks of %d KiB; WARM pass measured%n",
                        FILE_BYTES / (1024 * 1024),
                        blocks,
                        CACHE_BLOCK_SIZE / 1024
                    )
            );
        sb.append(String.format("%n%-36s %16s %16s%n", "metric", "POOLED", "BYPASS"));
        sb.append(String.format("%-36s %16s %16s%n", "-".repeat(36), "-".repeat(16), "-".repeat(16)));
        row(sb, "heap allocated (MiB)", mib(pooled.heapBytes()), mib(bypass.heapBytes()));
        row(sb, "heap per block (KiB)", perBlock(pooled.heapBytes(), blocks), perBlock(bypass.heapBytes(), blocks));
        row(sb, "direct delta (MiB)", mib(pooled.directBytes()), mib(bypass.directBytes()));
        row(sb, "direct buffer count delta", String.valueOf(pooled.directCount()), String.valueOf(bypass.directCount()));
        sb.append(String.format("%n%-36s %16s %16s%n", "counter", "POOLED", "BYPASS"));
        sb.append(String.format("%-36s %16s %16s%n", "-".repeat(36), "-".repeat(16), "-".repeat(16)));
        for (String k : new TreeSet<>(union(pooled.counters(), bypass.counters()))) {
            row(sb, k, String.valueOf(pooled.counters().getOrDefault(k, 0L)), String.valueOf(bypass.counters().getOrDefault(k, 0L)));
        }
        sb.append("=================================================================").append(System.lineSeparator());
        LOGGER.info(sb.toString());
        // stdout too: the report IS the point of this test and gradle drops INFO by default.
        System.out.println(sb);
    }

    private static Set<String> union(Map<String, Long> a, Map<String, Long> b) {
        final Set<String> s = new HashSet<>(a.keySet());
        s.addAll(b.keySet());
        return s;
    }

    private static void row(StringBuilder sb, String name, String a, String b) {
        sb.append(String.format("%-36s %16s %16s%n", name, a, b));
    }

    private static String mib(long bytes) {
        return String.format("%.2f", bytes / (1024.0 * 1024.0));
    }

    private static String perBlock(long bytes, long blocks) {
        return blocks == 0 ? "n/a" : String.format("%.1f", bytes / 1024.0 / blocks);
    }
}
