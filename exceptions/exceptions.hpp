/**
 * @file exceptions.hpp
 * @brief Exception types thrown by Sylvite operations.
 *
 * Defines a hierarchy of exceptions that provide detailed error information
 * when crypto operations fail. All exceptions inherit from `sodium_exception`,
 * which itself inherits from std::exception.
 *
 * Exception hierarchy:
 * @code
 * std::exception
 * └── sodium_exception           — base for all Sylvite exceptions
 *     ├── SodiumInitError        — libsodium failed to initialize
 *     ├── SodiumLogicError       — programming error (bad arguments, invalid state)
 *     ├── SodiumRuntimeError     — runtime failures (encryption failed, etc.)
 *     ├── SodiumInvalidSignature — signature verification failed
 *     ├── SodiumEmptyStringError — operation on empty String/Buffer
 *     ├── SodiumOutOfRangeError  — index out of bounds
 *     ├── SodiumDecodificationError — Base64/Hex decoding failed
 *     ├── SodiumDerivationError  — key derivation failed
 *     ├── SodiumIndexError      — index-related error
 *     ├── ConsumedKeyError       — key already used (for one-time key types)
 *     └── InvalidKeyError        — invalid key provided
 * @endcode
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T ignore exception handling in crypto code** — Catching and silently
 *    continuing after a crypto exception means you're operating with potentially
 *    broken security. Always handle exceptions appropriately.
 * - **DON'T leak sensitive data in exception messages** — Avoid including key
 *    material, plaintext, or other sensitive data in exception messages that
 *    might be logged.
 * - **DON'T use exception type to distinguish attack vs. bug** — Both tampering
 *    and programming errors can throw SodiumRuntimeError. Log the full context
 *    to distinguish them.
 * - **DON'T catch sodium_exception by value** — Always catch by const reference
 *    to avoid slicing and preserve the actual exception type.
 *
 * When to use which exception:
 * - **SodiumLogicError**: Thrown for programming errors — bad arguments,
 *   invalid sizes, invalid states. These indicate bugs in the caller's code.
 * - **SodiumRuntimeError**: Thrown when an operation fails at runtime
 *   (e.g., crypto operations returning nonzero status).
 * - **SodiumInvalidSignature**: Specifically for Ed25519 signature failures.
 *
 * @note All exception classes carry a human-readable message accessible via
 *       what(), suitable for logging and user-facing error reporting.
 */

#ifndef SYLVITE_ERROR_HPP
#define SYLVITE_ERROR_HPP

#include <exception>
#include <string>

namespace sylvite::exceptions {

/**
 * @brief Base exception class for all Sylvite errors.
 *
 * All library exceptions inherit from this class. It stores an error
 * message that can be retrieved via what().
 *
 * @par Error handling idiom:
 * @code
 * try {
 *     auto ct = XChaCha20Box::encrypt(data, key);
 * } catch (const sylvite::exceptions::sodium_exception& e) {
 *     std::cerr << "Crypto error: " << e.what() << '\n';
 * }
 * @endcode
 */
class sodium_exception : public std::exception {
    std::string error_;
    public:
    /** @brief Construct with a std::string message. */
    explicit sodium_exception(const std::string& e) : error_(e) {}
    /** @brief Construct with a C-string message. */
    explicit sodium_exception(const char* e) : error_(e) {}
    /** @brief Returns the error message. */
    const char* what() const noexcept override {
        return error_.c_str();
    }
};

/**
 * @brief Thrown when libsodium fails to initialize.
 *
 * Indicates that sodium_init() returned an error, which can happen if:
 * - The system's entropy source is unavailable
 * - The library is already being accessed from within a signal handler
 * - The library binary is corrupted or incompatible
 *
 * @par Mitigation:
 *      On Unix systems, libsodium uses /dev/urandom. On Windows it uses
 *      CryptGenRandom(). If both fail, initialization fails.
 */
class SodiumInitError : public sodium_exception {
    public:
    SodiumInitError() : sodium_exception("sodium_init failed to initialize safely.") {}
};

/**
 * @brief Thrown for programming errors — invalid arguments, sizes, or states.
 *
 * These are bugs in the calling code, not runtime failures. Examples:
 * - Passing a key of the wrong size
 * - Using a nonce that was already used (nonce reuse)
 * - Calling finalize() twice on a hash stream
 * - Passing an empty buffer where non-empty is required
 *
 * @par Prevention:
 *      Most SodiumLogicError conditions are preventable by reading
 *      documentation and using correct sizes. Constants like
 *      `crypto_aead_xchacha20poly1305_ietf_KEYBYTES` are provided
 *      for this purpose.
 */
class SodiumLogicError : public sodium_exception {
    public:
    SodiumLogicError(const std::string& e) : sodium_exception(e) {}
    SodiumLogicError(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown for index-related errors in container access.
 *
 * Currently used by Base<T>::at() when bounds checking fails.
 */
class SodiumIndexError : public sodium_exception {
    public:
    SodiumIndexError(const std::string& e) : sodium_exception(e.c_str()) {}
    SodiumIndexError(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown when operating on an empty String or Buffer.
 *
 * Used when calling methods like `back()` on an empty String or Buffer.
 * The error message will identify which object was empty.
 */
class SodiumEmptyStringError : public sodium_exception {
    public:
    SodiumEmptyStringError(const std::string& e) : sodium_exception(e) {}
    SodiumEmptyStringError(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown when Base64 or Hex decoding fails.
 *
 * Indicates malformed input — wrong characters, incorrect padding,
 * wrong variant (URL-safe vs. standard Base64), or truncated data.
 */
class SodiumDecodificationError : public sodium_exception {
    public:
    SodiumDecodificationError(const std::string& e) : sodium_exception(e) {}
    SodiumDecodificationError(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown when key derivation (KDF) fails.
 *
 * Used by Argon2ID and HKDF when the underlying derivation function
 * returns an error. Usually indicates invalid parameters or resource
 * exhaustion (not enough memory for Argon2).
 */
class SodiumDerivationError : public sodium_exception {
    public:
    SodiumDerivationError(const std::string& e) : sodium_exception(e) {}
    SodiumDerivationError(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown when an index is out of valid range.
 *
 * Used by Base<T>::at() for bounds-checked access.
 * Unlike std::out_of_range, this is specific to Sylvite.
 */
class SodiumOutOfRangeError : public sodium_exception {
    public:
    SodiumOutOfRangeError(const std::string& e) : sodium_exception(e) {}
    SodiumOutOfRangeError(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown when a runtime crypto operation fails.
 *
 * Indicates that a crypto primitive returned a nonzero status code.
 * Unlike SodiumLogicError, this represents failures that can occur
 * even with valid inputs — corrupted ciphertext, resource exhaustion,
 * etc.
 *
 * @par Common causes:
 * - crypto_aead_*_decrypt returns nonzero: ciphertext corrupted or
 *   modified (authentication failure)
 * - crypto_box_seal_open returns nonzero: wrong recipient key pair
 * - crypto_sign_verify_detached returns nonzero: signature invalid
 */
class SodiumRuntimeError : public sodium_exception {
    public:
    SodiumRuntimeError(const std::string& e) : sodium_exception(e) {}
    SodiumRuntimeError(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown when Ed25519 signature verification fails.
 *
 * Specifically for Ed25519 signature failures. Unlike other runtime
 * errors, this is expected failure mode when verifying an invalid
 * signature — not necessarily an error condition in the program logic.
 *
 * @note This is thrown by sylvite::sign::verify() on an invalid
 *       signature. For a non-throwing alternative, use the bool-returning
 *       verify in HMAC-SHA* which returns false instead.
 */
class SodiumInvalidSignature : public sodium_exception {
    public:
    SodiumInvalidSignature(const std::string& e) : sodium_exception(e) {}
    SodiumInvalidSignature(const char* e) : sodium_exception(e) {}
};

/**
 * @brief Thrown when a token has expired beyond its TTL.
 *
 * Indicates that a token (e.g., a Natron token) was created further
 * in the past than the specified time-to-live (TTL). This is an
 * expected failure mode when checking token freshness — not necessarily
 * an error in program logic.
 *
 * @par Common causes:
 * - Token was issued long ago and is now stale
 * - TTL is set too short for the use case
 * - System clock drift causing incorrect age calculation
 *
 * @note This is thrown by Natron::decrypt() when the token's timestamp
 *       exceeds the configured TTL. For a non-throwing alternative,
 *       manually check token age before decryption.
 */
class SodiumExpiredTokenError : public sodium_exception {
    public:
    SodiumExpiredTokenError(const std::string& e) : sodium_exception(e) {}
    SodiumExpiredTokenError(const char* e) : sodium_exception(e) {}
};

} // namespace sylvite::exceptions

#endif
