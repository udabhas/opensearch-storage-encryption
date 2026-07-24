/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.action;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.concurrent.atomic.AtomicReference;

import org.opensearch.Version;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.IndexModule;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;

/**
 * Tests for {@link TransportGetIndexCountForKeyAction} — validates index counting,
 * encryption context parsing (split("=", 2), duplicate key handling, order independence).
 */
public class TransportGetIndexCountForKeyActionTests extends OpenSearchTestCase {

    private ClusterService clusterService;
    private TransportGetIndexCountForKeyAction action;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        clusterService = mock(ClusterService.class);
        action = new TransportGetIndexCountForKeyAction(mock(TransportService.class), mock(ActionFilters.class), clusterService);
    }

    public void testNoCryptoIndicesReturnsZero() {
        setupClusterState(buildIndex("plain-index", "niofs", "", "", ""));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "");
        assertEquals(0, count);
    }

    public void testMatchingCryptoIndexReturnsOne() {
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "project=myapp"));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "project=myapp");
        assertEquals(1, count);
    }

    public void testNonMatchingKeyReturnsZero() {
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "project=myapp"));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/different", "aws-kms", "project=myapp");
        assertEquals(0, count);
    }

    public void testNonMatchingProviderReturnsZero() {
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "project=myapp"));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "dummy", "project=myapp");
        assertEquals(0, count);
    }

    public void testMultipleIndicesCountsOnlyMatching() {
        setupClusterState(
            buildIndex("encrypted-1", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "project=myapp"),
            buildIndex("encrypted-2", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "project=myapp"),
            buildIndex("encrypted-other", "cryptofs", "arn:aws:kms:us-east-1:123:key/other", "aws-kms", "project=myapp"),
            buildIndex("plain-index", "niofs", "", "", "")
        );
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "project=myapp");
        assertEquals(2, count);
    }

    public void testEncryptionContextOrderIndependence() {
        // Index has "a=1,b=2" but request has "b=2,a=1" — should still match
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "a=1,b=2"));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "b=2,a=1");
        assertEquals(1, count);
    }

    public void testEncryptionContextValueWithEqualsSign() {
        // Value containing '=' (e.g., base64) — split("=", 2) handles this correctly
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "token=abc123def=="));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "token=abc123def==");
        assertEquals(1, count);
    }

    public void testEncryptionContextValidEntriesMatch() {
        // Both sides have the same valid entry — should match
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "valid=entry"));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "valid=entry");
        assertEquals(1, count);
    }

    public void testEncryptionContextMalformedEntryThrows() {
        // Malformed context in filter → parseEncryptionContext throws IllegalArgumentException
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "valid=entry"));
        GetIndexCountForKeyRequest request = new GetIndexCountForKeyRequest("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "keyonly");
        AtomicReference<Exception> exceptionRef = new AtomicReference<>();
        action.doExecute(null, request, new ActionListener<>() {
            @Override
            public void onResponse(GetIndexCountForKeyResponse response) {}

            @Override
            public void onFailure(Exception e) {
                exceptionRef.set(e);
            }
        });
        assertNotNull("Should fail on malformed context", exceptionRef.get());
        assertTrue(exceptionRef.get() instanceof IllegalArgumentException);
    }

    public void testEmptyEncryptionContextMatches() {
        setupClusterState(buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", ""));
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "");
        assertEquals(1, count);
    }

    public void testDuplicateKeysInContextFirstWins() {
        // "key=first,key=second" — first wins. Both sides have the same input so they match.
        setupClusterState(
            buildIndex("encrypted-index", "cryptofs", "arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "key=first,key=second")
        );
        int count = executeCount("arn:aws:kms:us-east-1:123:key/abc", "aws-kms", "key=first,key=second");
        assertEquals(1, count);
    }

    // --- Helpers ---

    private IndexMetadata buildIndex(String name, String storeType, String keyArn, String keyProvider, String encryptionContext) {
        Settings.Builder settingsBuilder = Settings
            .builder()
            .put(IndexMetadata.SETTING_INDEX_UUID, name + "-uuid")
            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
            .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 0)
            .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
            .put(IndexModule.INDEX_STORE_TYPE_SETTING.getKey(), storeType);

        if (!keyArn.isEmpty()) {
            settingsBuilder.put("index.store.crypto.kms.key_arn", keyArn);
        }
        if (!keyProvider.isEmpty()) {
            settingsBuilder.put("index.store.crypto.key_provider", keyProvider);
        }
        if (!encryptionContext.isEmpty()) {
            settingsBuilder.put("index.store.crypto.kms.encryption_context", encryptionContext);
        }

        return IndexMetadata.builder(name).settings(settingsBuilder).build();
    }

    private void setupClusterState(IndexMetadata... indices) {
        Metadata.Builder metadataBuilder = Metadata.builder();
        for (IndexMetadata index : indices) {
            metadataBuilder.put(index, false);
        }
        ClusterState state = ClusterState.builder(new org.opensearch.cluster.ClusterName("test")).metadata(metadataBuilder.build()).build();
        when(clusterService.state()).thenReturn(state);
    }

    private int executeCount(String keyId, String keyProvider, String encryptionContext) {
        GetIndexCountForKeyRequest request = new GetIndexCountForKeyRequest(keyId, keyProvider, encryptionContext);
        AtomicReference<GetIndexCountForKeyResponse> responseRef = new AtomicReference<>();
        AtomicReference<Exception> exceptionRef = new AtomicReference<>();

        action.doExecute(null, request, new ActionListener<>() {
            @Override
            public void onResponse(GetIndexCountForKeyResponse response) {
                responseRef.set(response);
            }

            @Override
            public void onFailure(Exception e) {
                exceptionRef.set(e);
            }
        });

        assertNull("Should not fail: " + exceptionRef.get(), exceptionRef.get());
        assertNotNull("Should have a response", responseRef.get());
        return responseRef.get().getCount();
    }
}
