/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.metrics;

public enum ErrorType {
    KMS_KEY_ERROR("kms_key_error"),
    INDEX_INPUT_ERROR("index_input_error"),
    INDEX_OUTPUT_ERROR("index_output_error"),
    DIRECTORY_CREATION_ERROR("directory_creation_error"),
    CLOSE_SEGMENT_ERROR("close_segment_error"),
    INC_SEGMENT_ERROR("inc_segment_error"),
    DEC_SEGMENT_ERROR("dec_segment_error");

    private final String value;

    ErrorType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
