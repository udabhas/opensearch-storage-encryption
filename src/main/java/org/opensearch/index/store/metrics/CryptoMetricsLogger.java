/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

import software.amazon.cloudwatchlogs.emf.exception.DimensionSetExceededException;
import software.amazon.cloudwatchlogs.emf.exception.InvalidDimensionException;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CryptoMetricsLogger {
    private static final String NAMESPACE = "OpenSearch/StorageEncryption";
    private static volatile CryptoMetricsLogger INSTANCE;
    private static final Logger logger = LogManager.getLogger(CryptoMetricsLogger.class);
    private final MetricsLogger metrics;

    public static class MetricsContext {
        private final String operation;
        private final String directoryType;

        public MetricsContext(String operation, String directoryType) {
            this.operation = operation;
            this.directoryType = directoryType;
        }

        public DimensionSet toDimensionSet() throws InvalidDimensionException, DimensionSetExceededException {
            return DimensionSet.of("Operation", operation, "DirectoryType", directoryType);
        }
    }

    private CryptoMetricsLogger() {
        MetricsLogger temp = null;
        try {
            temp = new MetricsLogger();
            temp.setNamespace(NAMESPACE);
        } catch (Exception ex) {
            logger.warn("Failed to initialize MetricsLogger", ex);
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

    public void recordBytes(String metricName, long bytes, MetricsContext context) {
        try {
            recordMetric(metricName, bytes, Unit.BYTES, context.toDimensionSet());
        } catch (Exception e) {
            logger.warn("Failed to record bytes metric: {}", metricName, e);
        }
    }

    public void recordCount(String metricName, long count, MetricsContext context) {
        try {
            recordMetric(metricName, count, Unit.COUNT, context.toDimensionSet());
        } catch (Exception e) {
            logger.warn("Failed to record count metric: {}", metricName, e);
        }
    }

    private void recordMetric(String metricName, Number value, Unit unit, DimensionSet dimensions) {
        try {
            if (metrics != null) {
                metrics.putDimensions(dimensions);
                metrics.putMetric(metricName, value.doubleValue(), unit);
                metrics.flush();
            }
        } catch (Exception e) {
            logger.warn("Failed to record metric: {}", metricName, e);
        }
    }
}