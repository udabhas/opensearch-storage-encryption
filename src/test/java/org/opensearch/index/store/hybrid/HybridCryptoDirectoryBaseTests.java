/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.hybrid;

import java.io.IOException;
import java.nio.file.Path;

import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.tests.util.LuceneTestCase.AwaitsFix;
import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.CryptoTestDirectoryFactory;
import org.opensearch.index.store.OpenSearchBaseDirectoryTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

/**
 * Runs Lucene's full directory contract test suite against {@link HybridCryptoDirectory} as a whole,
 * treating it as a black box with its real production routing (see
 * {@link CryptoTestDirectoryFactory#createHybridCryptoDirectory}). The directory's internal
 * delegation between the NIO crypto path and the BufferPool encryption path is an implementation
 * detail: this suite only asserts that every Lucene directory operation behaves correctly through
 * the Hybrid façade.
 *
 * <p>Note on coverage: the Lucene contract exercises extensionless file names (e.g. "foobar",
 * "byte"), which {@code HybridCryptoDirectory} routes to the NIO crypto path
 * ({@code delegeteBufferPool("")} is false). The encrypted BufferPool read path — used in production
 * for non-NIO extensions — is therefore not exercised by this black-box suite.
 */
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class HybridCryptoDirectoryBaseTests extends OpenSearchBaseDirectoryTestCase {

    @Override
    protected Directory getDirectory(Path file) throws IOException {
        return CryptoTestDirectoryFactory.createHybridCryptoDirectory(file, FSLockFactory.getDefault());
    }

    @Override
    public void testCreateTempOutput() throws Throwable {
        try (Directory dir = getDirectory(createTempDir())) {
            CryptoTestDirectoryFactory.assertTempOutputRoundTrip(dir, atLeast(50), () -> newIOContext(random()));
        }
    }

    @Override
    @AwaitsFix(bugUrl = "https://github.com/opensearch-project/opensearch-storage-encryption/issues/47")
    public void testSliceOutOfBounds() {}

    @Override
    @AwaitsFix(bugUrl = "https://github.com/opensearch-project/opensearch-storage-encryption/issues/47")
    public void testThreadSafetyInListAll() {}
}
