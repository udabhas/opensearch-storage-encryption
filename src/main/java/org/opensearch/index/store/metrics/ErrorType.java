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
    DEC_SEGMENT_ERROR("dec_segment_error"),

    // Encrypted-translog failure classes. Emitted through the existing crypto.error.total flow
    // (differentiated by the error_type tag) rather than as new base metrics — the translog package
    // emits no base metrics of its own, so these turn its fail-closed data-integrity/durability
    // events into alarmable signals. See CryptoMetricsService#recordError.
    /**
     * AES-GCM authentication-tag verification failed on a translog frame decrypt (AEADBadTag): frame
     * tampering, corruption, or key/nonce reuse. Known incident class — should alarm immediately.
     */
    TRANSLOG_DECRYPT_TAG_FAILURE("translog_decrypt_tag_failure"),
    /**
     * Structural corruption detected during the recovery scan or read: header/super-header CRC mismatch,
     * frame sequence break, logical-offset break, or truncation. Fail-closed (shard fails init unless at EOF).
     */
    TRANSLOG_CORRUPTION("translog_corruption"),
    /**
     * The current key/epoch cannot decrypt the translog (key rotation out of sync, wrong key material).
     * Data is inaccessible — fail-closed.
     */
    TRANSLOG_KEY_EPOCH_MISMATCH("translog_key_epoch_mismatch"),
    /**
     * Refused to append to a non-empty encrypted translog on reopen — doing so would reuse a GCM nonce
     * (cryptographic weakness). Indicates a corrupted / partially-downloaded translog or lost frame-manager state.
     */
    TRANSLOG_NONCE_REUSE_GUARD("translog_nonce_reuse_guard"),
    /**
     * I/O failure on the translog write/seal path (short write, force/close seal failure): frame not durably
     * persisted / final tag missing. Durability violation.
     */
    TRANSLOG_IO_ERROR("translog_io_error"),
    /**
     * Translog crypto initialization / remote re-encrypt failure (channel-factory, transfer-manager, or
     * re-encrypt-downloaded-files). Shard fails to initialize (fail-closed); SSE-KMS download-recovery path.
     */
    TRANSLOG_INIT_ERROR("translog_init_error"),

    // Read-path / pool / cipher failure classes. Emitted through the existing crypto.error.total flow
    // (differentiated by the error_type tag) rather than as new base counters — reusing one counter with
    // an error_type tag keeps the metric surface small, and the error dashboard already
    // segregates by error_type. See CryptoMetricsService#recordError. (Latency lives in the separate
    // crypto.kms.call histogram, which a count-only error counter cannot hold.)
    /**
     * A Direct-I/O short/zero-byte read had to be retried (NFS/EFS cache staleness). A silent-corruption
     * precursor under the unauthenticated AES-CTR read path.
     */
    READ_SHORT_READ_RETRY("read_short_read_retry"),
    /**
     * A pool buffer acquire timed out with the memory-pressure throttle engaged — the caller waited out its
     * whole deadline while back-pressure was active. RED-risk under sustained pressure.
     */
    POOL_ACQUIRE_TIMEOUT_THROTTLE("pool_acquire_timeout_throttle"),
    /**
     * A pool buffer acquire timed out over the allocation limit (no throttle) — GC/zombie-buffer reclaim lag,
     * a distinct failure mode from a memory-pressure throttle.
     */
    POOL_ACQUIRE_TIMEOUT_ALLOCATION_LIMIT("pool_acquire_timeout_allocation_limit"),
    /**
     * A pool buffer acquire failed fast because the stall loop is disabled (fail-fast-over-limit is configured on).
     */
    POOL_ACQUIRE_TIMEOUT_STALL_DISABLED("pool_acquire_timeout_stall_disabled"),
    /**
     * AES per-frame decrypt failed on the niofs read path (cipher error). Surfaces later as a Lucene
     * CRC / CorruptIndexException if unhandled.
     */
    NIOFS_DECRYPT_FAILURE("niofs_decrypt_failure"),
    /**
     * GCM cipher init failed on the niofs write path. This throws a RuntimeException (not IOException) and so
     * bypasses INDEX_OUTPUT_ERROR entirely — recorded explicitly so a write-path cipher fault is not silent.
     */
    NIOFS_ENCRYPT_INIT_FAILURE("niofs_encrypt_init_failure"),
    /**
     * GCM tag finalization failed on the niofs write path (footer tags may be corrupt). Also a RuntimeException
     * path that bypasses INDEX_OUTPUT_ERROR.
     */
    NIOFS_ENCRYPT_FINALIZE_FAILURE("niofs_encrypt_finalize_failure");

    private final String value;

    ErrorType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
