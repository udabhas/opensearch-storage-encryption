/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.telemetry.metrics.Counter;
import org.opensearch.telemetry.metrics.Histogram;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.telemetry.metrics.tags.Tags;
import org.opensearch.telemetry.tracing.Tracer;

/**
 * Simple metrics collector for crypto operations using log-based approach
 */
public class CryptoMetrics {
    private static final Logger logger = LogManager.getLogger("crypto.metrics");
    private static volatile CryptoMetrics instance;
    private Tracer tracer;
    private MetricsRegistry metricsRegistry;
    private Counter operationsCounter;
    private Histogram latencyHistogram;
    private Counter bytesCounter;
    
    public static CryptoMetrics getInstance() {
        return getInstance(null, null);
    }
    
    public static CryptoMetrics getInstance(Tracer tracer, MetricsRegistry metricsRegistry) {
        if (instance == null) {
            synchronized (CryptoMetrics.class) {
                if (instance == null) {
                    instance = new CryptoMetrics();
                }
            }
        }
        if (tracer != null) {
            instance.tracer = tracer;
        }
        if (metricsRegistry != null) {
            instance.metricsRegistry = metricsRegistry;
            instance.initTelemetryMetrics();
        }
        return instance;
    }
    
    private void initTelemetryMetrics() {
        if (metricsRegistry != null) {
            operationsCounter = metricsRegistry.createCounter("crypto.operations.total", "Total crypto operations", "count");
            latencyHistogram = metricsRegistry.createHistogram("crypto.latency", "Crypto operation latency", "ms");
            bytesCounter = metricsRegistry.createCounter("crypto.bytes.total", "Total bytes processed", "bytes");
        }
    }
    
    public void recordOperation(long latencyMs, String operation, boolean success, long bytes) {
        // Add telemetry metrics
        Tags tags = Tags.create().addTag("operation", operation).addTag("success", String.valueOf(success));
        
        if (operationsCounter != null) {
            operationsCounter.add(1.0, tags);
        }
        if (latencyHistogram != null) {
            latencyHistogram.record(latencyMs, tags);
        }
        if (bytesCounter != null && bytes > 0) {
            bytesCounter.add(bytes, tags);
        }
    }
}