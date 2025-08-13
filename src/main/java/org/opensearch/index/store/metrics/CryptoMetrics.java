/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Simple metrics collector for crypto operations using log-based approach
 */
public class CryptoMetrics {
    private static final Logger logger = LogManager.getLogger("crypto.metrics");
    private static volatile CryptoMetrics instance;
    
    public static CryptoMetrics getInstance() {
        if (instance == null) {
            synchronized (CryptoMetrics.class) {
                if (instance == null) {
                    instance = new CryptoMetrics();
                }
            }
        }
        return instance;
    }
    
    public void recordOperation(long latencyMs, String operation, boolean success, long bytes) {
        logger.info("crypto.{}.operations{{success={}}} = 1.0", operation, success);
        logger.info("crypto.{}.latency{{success={}}} = {}ms", operation, success, latencyMs);
        if (bytes > 0) {
            logger.info("crypto.{}.bytes{{success={}}} = {}", operation, success, bytes);
        }
    }
}