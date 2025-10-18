/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import static org.opensearch.index.store.cipher.AesCipherFactory.computeOffsetIVForAesGcmEncrypted;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import org.opensearch.common.SuppressForbidden;

/**
 * Provides native bindings to OpenSSL EVP_aes_256_ctr using the Java Panama FFI.
 * This class is thread-safe as it creates new cipher contexts for each encryption operation.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "Uses Panama FFI for OpenSSL native function access")
@SuppressWarnings("preview")
public final class OpenSslNativeCipher {
    static final int AES_BLOCK_SIZE = 16;
    static final int AES_256_KEY_SIZE = 32;

    public static final MethodHandle EVP_CIPHER_CTX_new;
    public static final MethodHandle EVP_CIPHER_CTX_free;
    public static final MethodHandle EVP_EncryptInit_ex;
    public static final MethodHandle EVP_EncryptUpdate;
    public static final MethodHandle EVP_EncryptFinal_ex;
    public static final MethodHandle EVP_DecryptInit_ex;
    public static final MethodHandle EVP_DecryptUpdate;
    public static final MethodHandle EVP_DecryptFinal_ex;
    public static final MethodHandle EVP_CIPHER_CTX_ctrl;
    public static final MethodHandle EVP_aes_256_ctr;
    public static final MethodHandle EVP_aes_256_gcm;

    public static final int EVP_CTRL_GCM_GET_TAG = 0x10;
    public static final int EVP_CTRL_GCM_SET_TAG = 0x11;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIBCRYPTO = loadLibcrypto();

    private static SymbolLookup loadLibcrypto() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);

        if (os.contains("mac")) {
            // Common Homebrew path for OpenSSL on macOS
            String[] macPaths = {
                "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",   // Apple Silicon (M1/M2)
                "/usr/local/opt/openssl@3/lib/libcrypto.dylib"       // Intel Macs
            };

            for (String path : macPaths) {
                Path p = Path.of(path);
                if (Files.exists(p)) {
                    return SymbolLookup.libraryLookup(p, Arena.global());
                }
            }

            throw new RuntimeException("Could not find libcrypto.dylib in expected macOS locations.");
        } else if (os.contains("linux")) {
            try {
                // Try OpenSSL 3 first
                String[] linuxPaths = {
                    "/lib64/libcrypto.so.3",     // OpenSSL 3
                    "/lib64/libcrypto.so.1.1",   // OpenSSL 1.1 fallback
                    "/lib64/libcrypto.so.10",    // Legacy systems
                    "/lib64/libcrypto.so",       // Generic symlink
                    "/lib/libcrypto.so.3",
                    "/lib/libcrypto.so" };

                for (String path : linuxPaths) {
                    Path p = Path.of(path);
                    if (Files.exists(p)) {
                        return SymbolLookup.libraryLookup(p, Arena.global());
                    }
                }

                throw new RuntimeException("Could not find libcrypto in known Linux paths.");
            } catch (RuntimeException e) {
                throw new RuntimeException("Failed to load libcrypto", e);
            }
        } else {
            throw new UnsupportedOperationException("Unsupported OS: " + os);
        }
    }

    /**
     * Custom exception for OpenSSL-related errors during native cipher operations.
     */
    public static class OpenSslException extends RuntimeException {
        /**
         * Constructs an OpenSslException with the specified detail message.
         *
         * @param message the detail message explaining the error condition
         */
        public OpenSslException(String message) {
            super(message);
        }

        /**
         * Constructs an OpenSslException with the specified detail message and cause.
         *
         * @param message the detail message explaining the error condition
         * @param cause the underlying cause of this exception
         */
        public OpenSslException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static {
        try {
            EVP_CIPHER_CTX_new = LINKER
                .downcallHandle(LIBCRYPTO.find("EVP_CIPHER_CTX_new").orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS));

            EVP_CIPHER_CTX_free = LINKER
                .downcallHandle(LIBCRYPTO.find("EVP_CIPHER_CTX_free").orElseThrow(), FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

            EVP_EncryptInit_ex = LINKER
                .downcallHandle(
                    LIBCRYPTO.find("EVP_EncryptInit_ex").orElseThrow(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS
                        )
                );

            EVP_EncryptUpdate = LINKER
                .downcallHandle(
                    LIBCRYPTO.find("EVP_EncryptUpdate").orElseThrow(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, // ctx
                            ValueLayout.ADDRESS, // out
                            ValueLayout.ADDRESS, // outLen
                            ValueLayout.ADDRESS, // in
                            ValueLayout.JAVA_INT // inLen
                        )
                );

            EVP_aes_256_ctr = LINKER
                .downcallHandle(LIBCRYPTO.find("EVP_aes_256_ctr").orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS));

            EVP_aes_256_gcm = LINKER
                .downcallHandle(LIBCRYPTO.find("EVP_aes_256_gcm").orElseThrow(), FunctionDescriptor.of(ValueLayout.ADDRESS));

            EVP_EncryptFinal_ex = LINKER
                .downcallHandle(
                    LIBCRYPTO.find("EVP_EncryptFinal_ex").orElseThrow(),
                    FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                    )
                );

            EVP_CIPHER_CTX_ctrl = LINKER
                .downcallHandle(
                    LIBCRYPTO.find("EVP_CIPHER_CTX_ctrl").orElseThrow(),
                    FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS
                    )
                );

            EVP_DecryptInit_ex = LINKER
                .downcallHandle(
                    LIBCRYPTO.find("EVP_DecryptInit_ex").orElseThrow(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS
                        )
                );

            EVP_DecryptUpdate = LINKER
                .downcallHandle(
                    LIBCRYPTO.find("EVP_DecryptUpdate").orElseThrow(),
                    FunctionDescriptor
                        .of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS,
                            ValueLayout.JAVA_INT
                        )
                );

            EVP_DecryptFinal_ex = LINKER
                .downcallHandle(
                    LIBCRYPTO.find("EVP_DecryptFinal_ex").orElseThrow(),
                    FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS
                    )
                );

        } catch (Throwable t) {
            throw new OpenSslException("Failed to initialize OpenSSL method handles via Panama", t);
        }
    }

    /**
     * Encrypts the input data using AES-256-CTR mode with file position offset.
     * Thread-safe - creates a new cipher context for each call.
     *
     * @param key   The 32-byte encryption key (must not be null)
     * @param iv    The 16-byte initialization vector (must not be null)
     * @param input The data to encrypt (must not be null or empty)
     * @param filePosition The file position offset for IV computation
     * @return The encrypted data
     * @throws IllegalArgumentException if the input parameters are invalid
     * @throws OpenSslException if encryption fails
     * @throws Throwable if there's an unexpected error
     */
    public static byte[] encrypt(byte[] key, byte[] iv, byte[] input, long filePosition) throws Throwable {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid IV length: expected " + AES_BLOCK_SIZE + " bytes");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ctx = (MemorySegment) EVP_CIPHER_CTX_new.invoke();
            if (ctx.address() == 0) {
                throw new OpenSslException("EVP_CIPHER_CTX_new failed");
            }

            try {
                MemorySegment cipher = (MemorySegment) EVP_aes_256_ctr.invoke();
                if (cipher.address() == 0) {
                    throw new OpenSslException("EVP_aes_256_ctr failed");
                }

                byte[] adjustedIV = computeOffsetIVForAesGcmEncrypted(iv, filePosition);
                MemorySegment keySeg = arena.allocateArray(ValueLayout.JAVA_BYTE, key);
                MemorySegment ivSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, adjustedIV);

                int rc = (int) EVP_EncryptInit_ex.invoke(ctx, cipher, MemorySegment.NULL, keySeg, ivSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptInit_ex failed");
                }

                int skipBytes = (int) (filePosition % AES_BLOCK_SIZE);
                if (skipBytes > 0) {
                    MemorySegment dummyIn = arena.allocateArray(ValueLayout.JAVA_BYTE, new byte[skipBytes]);
                    MemorySegment dummyOut = arena.allocate(skipBytes + AES_BLOCK_SIZE, 1);
                    MemorySegment dummyLen = arena.allocate(ValueLayout.JAVA_INT);
                    EVP_EncryptUpdate.invoke(ctx, dummyOut, dummyLen, dummyIn, skipBytes);
                }

                MemorySegment inSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, input);
                MemorySegment outSeg = arena.allocate(input.length, 1);
                MemorySegment outLen = arena.allocate(ValueLayout.JAVA_INT);

                rc = (int) EVP_EncryptUpdate.invoke(ctx, outSeg, outLen, inSeg, input.length);
                if (rc != 1) {
                    throw new OpenSslException("EVP_EncryptUpdate failed");
                }

                int bytesWritten = outLen.get(ValueLayout.JAVA_INT, 0);
                return outSeg.asSlice(0, bytesWritten).toArray(ValueLayout.JAVA_BYTE);
            } finally {
                EVP_CIPHER_CTX_free.invoke(ctx);
            }
        }
    }

    /**
     * Initializes a GCM cipher context for streaming encryption.
     */
    public static MemorySegment initGCMCipher(byte[] key, byte[] iv, long filePosition) throws Throwable {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid IV length: expected " + AES_BLOCK_SIZE + " bytes");
        }

        MemorySegment ctx = (MemorySegment) EVP_CIPHER_CTX_new.invoke();
        if (ctx.address() == 0) {
            throw new OpenSslException("EVP_CIPHER_CTX_new failed");
        }

        MemorySegment cipher = (MemorySegment) EVP_aes_256_gcm.invoke();
        if (cipher.address() == 0) {
            EVP_CIPHER_CTX_free.invoke(ctx);
            throw new OpenSslException("EVP_aes_256_gcm failed");
        }

        byte[] gcmIV = new byte[12];
        System.arraycopy(iv, 0, gcmIV, 0, 12);

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySeg = arena.allocateArray(ValueLayout.JAVA_BYTE, key);
            MemorySegment ivSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, gcmIV);

            int rc = (int) EVP_EncryptInit_ex.invoke(ctx, cipher, MemorySegment.NULL, keySeg, ivSeg);
            if (rc != 1) {
                EVP_CIPHER_CTX_free.invoke(ctx);
                throw new OpenSslException("EVP_EncryptInit_ex failed");
            }
            return ctx;

        }
    }

    /**
     * Encrypts data using an initialized GCM cipher context.
     */
    public static byte[] encryptUpdate(MemorySegment ctx, byte[] input) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment inSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, input);
            MemorySegment outSeg = arena.allocate(input.length, 1);
            MemorySegment outLen = arena.allocate(ValueLayout.JAVA_INT);

            int rc = (int) EVP_EncryptUpdate.invoke(ctx, outSeg, outLen, inSeg, input.length);
            if (rc != 1) {
                throw new OpenSslException("EVP_EncryptUpdate failed");
            }
            int bytesWritten = outLen.get(ValueLayout.JAVA_INT, 0);
            return outSeg.asSlice(0, bytesWritten).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    /**
     * Finalizes GCM encryption, returns the authentication tag, and frees the context.
     */
    public static byte[] finalizeAndGetTag(MemorySegment ctx) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment finalOut = arena.allocate(AES_BLOCK_SIZE, 1);
            MemorySegment finalLen = arena.allocate(ValueLayout.JAVA_INT);

            int rc = (int) EVP_EncryptFinal_ex.invoke(ctx, finalOut, finalLen);
            if (rc != 1) {
                throw new OpenSslException("EVP_EncryptFinal_ex failed");
            }

            MemorySegment tagSeg = arena.allocate(16, 1);
            rc = (int) EVP_CIPHER_CTX_ctrl.invoke(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagSeg);
            if (rc != 1) {
                throw new OpenSslException("Failed to get GCM tag");
            }

            return tagSeg.toArray(ValueLayout.JAVA_BYTE);
        } finally {
            EVP_CIPHER_CTX_free.invoke(ctx);
        }
    }

    /**
     * Decrypts GCM data and verifies authentication tag.
     */
    public static byte[] decryptWithTag(byte[] key, byte[] iv, byte[] ciphertext) throws Throwable {
        if (key == null || key.length != AES_256_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid key length: expected " + AES_256_KEY_SIZE + " bytes");
        }
        if (iv == null || iv.length != AES_BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid IV length: expected " + AES_BLOCK_SIZE + " bytes");
        }
        if (ciphertext == null || ciphertext.length < 16) {
            throw new IllegalArgumentException("Ciphertext must be at least 16 bytes");
        }

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ctx = (MemorySegment) EVP_CIPHER_CTX_new.invoke();
            if (ctx.address() == 0) {
                throw new OpenSslException("EVP_CIPHER_CTX_new failed");
            }

            try {
                MemorySegment cipher = (MemorySegment) EVP_aes_256_gcm.invoke();
                if (cipher.address() == 0) {
                    throw new OpenSslException("EVP_aes_256_gcm failed");
                }

                byte[] gcmIV = new byte[12];
                System.arraycopy(iv, 0, gcmIV, 0, 12);

                MemorySegment keySeg = arena.allocateArray(ValueLayout.JAVA_BYTE, key);
                MemorySegment ivSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, gcmIV);

                int rc = (int) EVP_DecryptInit_ex.invoke(ctx, cipher, MemorySegment.NULL, keySeg, ivSeg);
                if (rc != 1) {
                    throw new OpenSslException("EVP_DecryptInit_ex failed");
                }

                int dataLen = ciphertext.length - 16;
                MemorySegment inSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, ciphertext);
                MemorySegment outSeg = arena.allocate(dataLen, 1);
                MemorySegment outLen = arena.allocate(ValueLayout.JAVA_INT);

                rc = (int) EVP_DecryptUpdate.invoke(ctx, outSeg, outLen, inSeg, dataLen);
                if (rc != 1) {
                    throw new OpenSslException("EVP_DecryptUpdate failed");
                }

                byte[] tag = new byte[16];
                System.arraycopy(ciphertext, dataLen, tag, 0, 16);
                MemorySegment tagSeg = arena.allocateArray(ValueLayout.JAVA_BYTE, tag);

                rc = (int) EVP_CIPHER_CTX_ctrl.invoke(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagSeg);
                if (rc != 1) {
                    throw new OpenSslException("Failed to set GCM tag");
                }

                MemorySegment finalOut = arena.allocate(AES_BLOCK_SIZE, 1);
                MemorySegment finalLen = arena.allocate(ValueLayout.JAVA_INT);

                rc = (int) EVP_DecryptFinal_ex.invoke(ctx, finalOut, finalLen);
                if (rc != 1) {
                    throw new OpenSslException("GCM tag verification failed");
                }

                int bytesWritten = outLen.get(ValueLayout.JAVA_INT, 0);
                return outSeg.asSlice(0, bytesWritten).toArray(ValueLayout.JAVA_BYTE);
            } finally {
                EVP_CIPHER_CTX_free.invoke(ctx);
            }
        }
    }

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private OpenSslNativeCipher() {
        // Utility class
    }
}