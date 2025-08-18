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
    private static final Logger logger = LogManager.getLogger(CryptoMetricsLogger.class);
    
    private static final ThreadLocal<MetricsLogger> THREAD_LOCAL_LOGGER = 
        ThreadLocal.withInitial(() -> {
            try {
                MetricsLogger ml = new MetricsLogger();
                ml.setNamespace(NAMESPACE);
                return ml;
            } catch (Exception e) {
                logger.warn("Failed to create MetricsLogger for thread: {}", Thread.currentThread().getName(), e);
                return null;
            }
        });

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
        // Private constructor to prevent instantiation
    }
    
    private static MetricsLogger getMetricsLogger() {
        return THREAD_LOCAL_LOGGER.get();
    }

    public static void recordBytes(String metricName, long bytes, MetricsContext context) {
        try {
            recordMetric(metricName, bytes, Unit.BYTES, context.toDimensionSet());
        } catch (Exception e) {
            logger.warn("Failed to record bytes metric: {}", metricName, e);
        }
    }

    public static void recordCount(String metricName, long count, MetricsContext context) {
        try {
            recordMetric(metricName, count, Unit.COUNT, context.toDimensionSet());
        } catch (Exception e) {
            logger.warn("Failed to record count metric: {}", metricName, e);
        }
    }

    public static void recordRate(String metricName, double rate, Unit unit, MetricsContext context) {
        try {
            recordMetric(metricName, rate, unit, context.toDimensionSet());
        } catch (Exception e) {
            logger.warn("Failed to record rate metric: {}", metricName, e);
        }
    }

    private static void recordMetric(String metricName, Number value, Unit unit, DimensionSet dimensions) {
        try {
            MetricsLogger metrics = getMetricsLogger();
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