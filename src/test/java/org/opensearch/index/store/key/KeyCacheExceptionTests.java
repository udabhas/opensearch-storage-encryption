/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for {@link KeyCacheException} utility methods: classify and extractRootCauseMessage.
 */
public class KeyCacheExceptionTests extends OpenSearchTestCase {

    // --- extractRootCauseMessage ---

    public void testExtractRootCauseMessageNull() {
        assertEquals("Unknown error", KeyCacheException.extractRootCauseMessage(null));
    }

    public void testExtractRootCauseMessageSingleException() {
        Exception e = new RuntimeException("top-level message");
        assertEquals("top-level message", KeyCacheException.extractRootCauseMessage(e));
    }

    public void testExtractRootCauseMessageNestedChain() {
        Exception root = new IllegalStateException("root cause");
        Exception mid = new RuntimeException("wrapper", root);
        Exception top = new Exception("top", mid);
        assertEquals("root cause", KeyCacheException.extractRootCauseMessage(top));
    }

    public void testExtractRootCauseMessageNullMessageFallsBackToClassName() {
        Exception e = new RuntimeException((String) null);
        assertEquals("RuntimeException", KeyCacheException.extractRootCauseMessage(e));
    }

    // --- classify ---

    public void testClassifyNullException() {
        assertEquals(FailureType.CRITICAL, KeyCacheException.classify(null));
    }

    public void testClassifyUnknownExceptionDefaultsToTransient() {
        assertEquals(FailureType.TRANSIENT, KeyCacheException.classify(new RuntimeException("some unknown error")));
    }

    public void testClassifyCriticalByAccessDeniedMessagePattern() {
        assertEquals(FailureType.CRITICAL, KeyCacheException.classify(new RuntimeException("access denied to key")));
    }

    public void testClassifyCriticalByKeyDisabledMessagePattern() {
        assertEquals(FailureType.CRITICAL, KeyCacheException.classify(new RuntimeException("key disabled")));
    }

    public void testClassifyTransientByRateExceededMessagePattern() {
        assertEquals(FailureType.TRANSIENT, KeyCacheException.classify(new RuntimeException("Rate exceeded for KMS")));
    }

    public void testClassifyTransientByThrottlingMessagePattern() {
        assertEquals(FailureType.TRANSIENT, KeyCacheException.classify(new RuntimeException("ThrottlingException: slow down")));
    }

    public void testClassifyCriticalByExceptionType() {
        Exception e = new RuntimeException("wrapper", new DisabledException("key is disabled"));
        assertEquals(FailureType.CRITICAL, KeyCacheException.classify(e));
    }

    public void testClassifyTransientByExceptionType() {
        Exception e = new RuntimeException("wrapper", new ThrottlingException("too many requests"));
        assertEquals(FailureType.TRANSIENT, KeyCacheException.classify(e));
    }

    // --- Exception stubs matching hasExceptionType checks in classify() ---

    private static class DisabledException extends RuntimeException {
        DisabledException(String msg) {
            super(msg);
        }
    }

    private static class ThrottlingException extends RuntimeException {
        ThrottlingException(String msg) {
            super(msg);
        }
    }
}
