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
    private final MetricsLogger metrics;
    
    public CryptoMetricsLogger() {
        MetricsLogger temp = null;
        try {
            temp = new MetricsLogger();
            temp.setNamespace(NAMESPACE);
        } catch (Exception ex) {
            // do nothing for now
        }
        this.metrics = temp;
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
}