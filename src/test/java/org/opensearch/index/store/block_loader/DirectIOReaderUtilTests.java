/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests the Direct-I/O aligned read helper in {@link DirectIOReaderUtil}.
 *
 * <p>Regression coverage for the shard-RED corruption bug where a read of a small metadata file whose
 * size is not a filesystem-block multiple (e.g. Lucene {@code _0_Lucene90FieldsIndex-doc_ids_0.tmp},
 * observed at 125 and 1256 bytes) issued a second {@code O_DIRECT} positional read at the unaligned
 * end-of-file position. The JDK rejects that with
 * {@code "Channel position (N) is not a multiple of the block size (M)"}, which tragically closed the
 * Lucene {@code IndexWriter} and permanently failed the shard. The read loop must stop on a
 * sub-block (EOF) read rather than resume at an unaligned position.
 */
public class DirectIOReaderUtilTests extends OpenSearchTestCase {

    /**
     * Opens a Direct-I/O read channel for {@code file}, or returns {@code null} if the JVM/filesystem
     * does not support {@code O_DIRECT} (e.g. tmpfs), so the test can be skipped rather than fail.
     */
    private static FileChannel tryOpenDirect(Path file) {
        try {
            return FileChannel.open(file, StandardOpenOption.READ, DirectIOReaderUtil.getDirectOpenOption());
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * A file smaller than one block, read with a multi-block-aligned request, must return exactly the
     * file's bytes without throwing the unaligned-position IOException. Pre-fix this threw at the
     * resumed read of position == fileSize.
     */
    public void testSubBlockFileReadDoesNotThrowUnalignedPosition() throws Exception {
        int blockSize = 4096;
        // 125 bytes: a small sub-block file size (e.g. a doc_ids temp file) that triggered the bug.
        byte[] content = new byte[125];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) (i & 0xFF);
        }

        Path dir = createTempDir();
        Path file = dir.resolve("_0_Lucene90FieldsIndex-doc_ids_0.tmp");
        Files.write(file, content);

        FileChannel channel = tryOpenDirect(file);
        assumeTrue("O_DIRECT not supported on this filesystem", channel != null);

        try (channel; Arena arena = Arena.ofConfined()) {
            // Request a full 8192-byte (2-block) read starting at offset 0 — the block loader's default.
            MemorySegment seg = DirectIOReaderUtil.directIOReadAligned(channel, 0, 8192, arena, blockSize);

            assertEquals("must return exactly the file's byte count", content.length, (int) seg.byteSize());
            byte[] got = seg.toArray(java.lang.foreign.ValueLayout.JAVA_BYTE);
            assertArrayEquals("returned bytes must match file content", content, got);
        }
    }

    /**
     * A read at a non-block-aligned offset into a sub-block file (offset within the first block) must
     * still return the requested tail bytes without an unaligned-resume throw.
     */
    public void testUnalignedOffsetIntoSubBlockFile() throws Exception {
        int blockSize = 4096;
        byte[] content = new byte[1256]; // the other production size observed.
        random().nextBytes(content);

        Path dir = createTempDir();
        Path file = dir.resolve("frag.tmp");
        Files.write(file, content);

        FileChannel channel = tryOpenDirect(file);
        assumeTrue("O_DIRECT not supported on this filesystem", channel != null);

        try (channel; Arena arena = Arena.ofConfined()) {
            int offset = 100;
            int length = 500;
            MemorySegment seg = DirectIOReaderUtil.directIOReadAligned(channel, offset, length, arena, blockSize);

            assertEquals(length, (int) seg.byteSize());
            byte[] got = seg.toArray(java.lang.foreign.ValueLayout.JAVA_BYTE);
            byte[] expected = new byte[length];
            System.arraycopy(content, offset, expected, 0, length);
            assertArrayEquals(expected, got);
        }
    }
}
