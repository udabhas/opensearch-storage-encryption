/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;

public class CryptoMetricsLogger {
    private static final String NAMESPACE = "OpenSearch/StorageEncryption";
    private static volatile CryptoMetricsLogger INSTANCE;
    private final MetricsLogger metrics;
    
    private CryptoMetricsLogger() {
        MetricsLogger temp = null;
        try {
            temp = new MetricsLogger();
            temp.setNamespace(NAMESPACE);
        } catch (Exception ex) {
            // do nothing for now
        }
        this.metrics = temp;
    }
    
    public static CryptoMetricsLogger getInstance() {
        if (INSTANCE == null) {
            synchronized (CryptoMetricsLogger.class) {
                if (INSTANCE == null) {
                    INSTANCE = new CryptoMetricsLogger();
                }
            }
        }
        return INSTANCE;
    }

    public void recordEncryptionLatency(double latencyMs, String operation) {
        try {
            if (metrics != null) {
                metrics.putDimensions(DimensionSet.of("Operation", operation));
                metrics.putMetric("EncryptionLatency", latencyMs, Unit.MILLISECONDS);
                metrics.flush();
            }
        } catch (Exception e) {
            // Silently fail for POC
        }
    }
    
    public void recordDecryptionLatency(double latencyMs, String operation) {
        try {
            if (metrics != null) {
                metrics.putDimensions(DimensionSet.of("Operation", operation));
                metrics.putMetric("DecryptionLatency", latencyMs, Unit.MILLISECONDS);
                metrics.flush();
            }
        } catch (Exception e) {
            // Silently fail for POC
        }
    }
    
    public void recordThroughput(double bytesPerSecond, String operation) {
        try {
            if (metrics != null) {
                metrics.putDimensions(DimensionSet.of("Operation", operation));
                metrics.putMetric("Throughput", bytesPerSecond, Unit.BYTES_SECOND);
                metrics.flush();
            }
        } catch (Exception e) {
            // Silently fail for POC
        }
    }
    
    public void recordMemoryUsage(long bytes, String operation) {
        try {
            if (metrics != null) {
                metrics.putDimensions(DimensionSet.of("Operation", operation));
                metrics.putMetric("MemoryUsage", bytes, Unit.BYTES);
                metrics.flush();
            }
        } catch (Exception e) {
            // Silently fail for POC
        }
    }
    
    public void recordFileSize(long bytes, String fileType) {
        try {
            if (metrics != null) {
                metrics.putDimensions(DimensionSet.of("FileType", fileType));
                metrics.putMetric("FileSize", bytes, Unit.BYTES);
                metrics.flush();
            }
        } catch (Exception e) {
            // Silently fail for POC
        }
    }
    
    public void recordIOOperations(long count, String operation) {
        try {
            if (metrics != null) {
                metrics.putDimensions(DimensionSet.of("Operation", operation));
                metrics.putMetric("IOOperations", count, Unit.COUNT);
                metrics.flush();
            }
        } catch (Exception e) {
            // Silently fail for POC
        }
    }
    
    public void recordKeyOperationLatency(double latencyMs, String keyOperation) {
        try {
            if (metrics != null) {
                metrics.putDimensions(DimensionSet.of("KeyOperation", keyOperation));
                metrics.putMetric("KeyOperationLatency", latencyMs, Unit.MILLISECONDS);
                metrics.flush();
            }
        } catch (Exception e) {
            // Silently fail for POC
        }
    }
}