/**
 * @file hmac.hpp
 * @brief HMAC-SHA-256 and HMAC-SHA-512 keyed hash functions.
 *
 * Provides HMAC (Hash-based Message Authentication Code) constructions:
 * - HMAC-SHA-256: Uses SHA-256 as the underlying hash
 * - HMAC-SHA-512: Uses SHA-512 as the underlying hash
 *
 * HMAC is a pseudorandom function that combines a key with a message
 * to produce an authentication tag. It is more secure than simply
 * concatenating key + message and hashing, because HMAC is resistant
 * to existential forgery under chosen-message attacks.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use HMAC for password hashing** — HMAC is not memory-hard and is
 *   vulnerable to GPU/ASIC attacks. Use Argon2ID for password-based key derivation.
 * - **DON'T use the same HMAC key for different purposes** — If you need keys for
 *   different purposes (e.g., one for authentication, one for encryption), derive
 *   separate keys using HKDF or by binding a purpose identifier to the HMAC.
 * - **DON'T use a key smaller than DIGEST_SIZE** — The key is internally padded or
 *   hashed. Using very short keys reduces security. A 32-byte key is recommended.
 * - **DON'T skip verification failures** — Even if you only use HMAC for integrity
 *   checks, always handle verification failures seriously. An attacker could be
 *   exploiting a tampered message if verification fails.
 *
 * @par Security properties:
 * - Keyed: requires knowledge of secret key to compute/verify
 * - Unforgeable: without the key, an attacker cannot produce a valid tag
 * - Deterministic: same key + message always produces same tag
 *
 * @par Use cases:
 * - Message authentication (prove sender knows key)
 * - Integrity verification (message wasn't tampered with)
 * - Password hashing (use Argon2ID instead for passwords)
 *
 * @par Difference from hash::Sha*::digest with key parameter:
 *      HMAC uses a specific construction (ipad/opad double-hash)
 *      that provides security proofs. Simply hashing key+data is
 *      NOT the same as HMAC and may be vulnerable to length-extension
 *      attacks on the underlying hash.
 *
 * @par Example — HMAC-SHA-256:
 * @code
 * auto tag = sylvite::hash::HmacSha256::mac(message, key);
 * bool valid = sylvite::hash::HmacSha256::verify(tag, message, key);
 * @endcode
 *
 * @par Example — streaming HMAC:
 * @code
 * sylvite::hash::HmacSha256::Stream hasher(key_span);
 * hasher.update(chunk1);
 * hasher.update(chunk2);
 * auto tag = hasher.finalize();
 * @endcode
 */

#ifndef SYLVITE_HMAC_HPP
#define SYLVITE_HMAC_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <span>
#include <stdexcept>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"
#include "../internal/noncemodify.hpp"

namespace sylvite::hash {

namespace HmacSha256 {

/// @brief HMAC-SHA-256 output size (32 bytes).
static constexpr std::size_t DIGEST_SIZE = crypto_auth_hmacsha256_BYTES;

/// @brief Required key size for HMAC-SHA-256 (32 bytes).
static constexpr std::size_t KEY_SIZE = crypto_auth_hmacsha256_KEYBYTES;

/**
 * @brief Compute an HMAC-SHA-256 authentication tag.
 *
 * @tparam T ContiguousByteContainer type for the message.
 *
 * @param input_ The message to authenticate.
 * @param key_ The secret key (must be exactly KEY_SIZE bytes).
 *
 * @return std::vector<std::uint8_t> The 32-byte authentication tag.
 *
 * @throw SodiumLogicError if the key size is not 32 bytes.
 * @throw sylvite::exceptions::SodiumRuntimeError if the HMAC computation fails.
 *
 * @par Example:
 * @code
 * auto tag = sylvite::hash::HmacSha256::mac(message, key);
 * @endcode
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> mac(
    const T& input_,
    std::span<const std::uint8_t> key_
) {
    if (key_.size() != KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid HMAC-SHA-256 key length. Expected " +
            std::to_string(KEY_SIZE) + " bytes, got " +
            std::to_string(key_.size())
        );
    }
    std::vector<std::uint8_t> out_(DIGEST_SIZE);
    if (crypto_auth_hmacsha256(
            out_.data(),
            reinterpret_cast<const unsigned char*>(input_.data()),
            input_.size(),
            key_.data()) != 0)
    {
        throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-256 failed.");
    }
    return out_;
}

/**
 * @brief Compute HMAC-SHA-256 for a std::string message.
 *
 * Convenience overload for string messages.
 *
 * @param input_ The message string to authenticate.
 * @param key_ The 32-byte secret key.
 *
 * @return std::vector<std::uint8_t> The 32-byte authentication tag.
 */
[[nodiscard]]
inline std::vector<std::uint8_t> mac(
    const std::string& input_,
    std::span<const std::uint8_t> key_
) {
    return mac<std::string>(input_, key_);
}

/**
 * @brief Verify an HMAC-SHA-256 tag.
 *
 * @tparam T ContiguousByteContainer type for the message.
 *
 * @param tag_ The 32-byte tag to verify.
 * @param input_ The message that was authenticated.
 * @param key_ The 32-byte secret key.
 *
 * @return bool true if the tag is valid, false if not.
 *
 * @throw SodiumLogicError if the key size is invalid.
 *
 * @par Return behavior:
 *      Unlike sylvite::sign::verify which throws on invalid signature,
 *      this function returns false instead. This is useful when an
 *      invalid HMAC is an expected/acceptable event, not an error.
 *
 * @par Example:
 * @code
 * if (HmacSha256::verify(tag, message, key)) {
 *     // message is authentic
 * } else {
 *     // message was tampered with or wrong key
 * }
 * @endcode
 */
template<sylvite::concepts::ContiguousByteContainer T>
inline bool verify(
    std::span<const std::uint8_t> tag_,
    const T& input_,
    std::span<const std::uint8_t> key_
) {
    if (tag_.size() != DIGEST_SIZE) return false;
    if (key_.size() != KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid HMAC-SHA-256 key length for verify."
        );
    }

    return crypto_auth_hmacsha256_verify(
        tag_.data(),
        reinterpret_cast<const unsigned char*>(input_.data()),
        input_.size(),
        key_.data()) == 0;
}

/**
 * @brief Streaming HMAC-SHA-256 state.
 *
 * Use for incremental authentication of data that arrives in chunks.
 *
 * @par Usage:
 * @code
 * sylvite::hash::HmacSha256::Stream hasher(key_span);
 * hasher.update(chunk1);
 * hasher.update(chunk2);
 * auto tag = hasher.finalize();
 * @endcode
 */
class Stream final : public sylvite::internal::NonCopyable {
    crypto_auth_hmacsha256_state state_;  ///< The libsodium HMAC state.
    bool finalized_ = false;            ///< Whether finalize() has been called.

public:
    /**
     * @brief Construct a streaming HMAC-SHA-256 hasher.
     *
     * @param key_ The secret key (32 bytes, or empty for null key).
     *
     * @throw sylvite::exceptions::SodiumRuntimeError if initialization fails.
     *
     * @par Note:
     *      An empty/null key is allowed by libsodium. This would be
     *      used in very specific protocols that require it.
     */
    explicit Stream(std::span<const std::uint8_t> key_ = {}) {
        if (crypto_auth_hmacsha256_init(
                &state_,
                key_.empty() ? nullptr : key_.data(),
                key_.size()) != 0)
        {
            throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-256 stream init failed.");
        }
    }

    /**
     * @brief Add a chunk of data to the HMAC.
     *
     * @tparam T ContiguousByteContainer type.
     * @param data_ The data chunk to incorporate.
     *
     * @return Stream& Reference to this (for chaining).
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    Stream& update(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError(
            "Cannot update a finalized HMAC-SHA-256 stream.");
        if (crypto_auth_hmacsha256_update(
                &state_,
                reinterpret_cast<const unsigned char*>(data_.data()),
                data_.size()) != 0)
        {
            throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-256 stream update failed.");
        }
        return *this;
    }

    /// @brief Overload for std::string.
    Stream& update(const std::string& data_) { return update<std::string>(data_); }

    /**
     * @brief Finalize the HMAC and return the 32-byte tag.
     *
     * @return std::vector<std::uint8_t> The authentication tag.
     */
    [[nodiscard]]
    std::vector<std::uint8_t> finalize() {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError(
            "HMAC-SHA-256 stream already finalized.");
        std::vector<std::uint8_t> out_(DIGEST_SIZE);
        if (crypto_auth_hmacsha256_final(&state_, out_.data()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-256 stream finalize failed.");
        finalized_ = true;
        return out_;
    }

    /// @brief Returns true if finalize() has been called.
    [[nodiscard]] bool is_finalized() const noexcept { return finalized_; }
};

} // namespace HmacSha256

namespace HmacSha512 {

/// @brief HMAC-SHA-512 output size (64 bytes).
static constexpr std::size_t DIGEST_SIZE = crypto_auth_hmacsha512_BYTES;

/// @brief Required key size for HMAC-SHA-512 (32 bytes, not 64!).
static constexpr std::size_t KEY_SIZE = crypto_auth_hmacsha512_KEYBYTES;

/**
 * @brief Compute an HMAC-SHA-512 authentication tag.
 *
 * @tparam T ContiguousByteContainer type for the message.
 *
 * @param input_ The message to authenticate.
 * @param key_ The secret key (must be exactly KEY_SIZE bytes).
 *
 * @return std::vector<std::uint8_t> The 64-byte authentication tag.
 *
 * @throw SodiumLogicError if the key size is not 32 bytes.
 * @throw sylvite::exceptions::SodiumRuntimeError if the HMAC computation fails.
 *
 * @par Note:
 *      HMAC-SHA-512 takes a 32-byte key, not a 64-byte key.
 *      This is by design (the key is hashed internally).
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> mac(
    const T& input_,
    std::span<const std::uint8_t> key_
) {
    if (key_.size() != KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid HMAC-SHA-512 key length. Expected " +
            std::to_string(KEY_SIZE) + " bytes, got " +
            std::to_string(key_.size())
        );
    }
    std::vector<std::uint8_t> out_(DIGEST_SIZE);
    if (crypto_auth_hmacsha512(
            out_.data(),
            reinterpret_cast<const unsigned char*>(input_.data()),
            input_.size(),
            key_.data()) != 0)
    {
        throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-512 failed.");
    }
    return out_;
}

/**
 * @brief Compute HMAC-SHA-512 for a std::string message.
 *
 * Convenience overload for string messages.
 *
 * @param input_ The message string to authenticate.
 * @param key_ The 32-byte secret key.
 *
 * @return std::vector<std::uint8_t> The 64-byte authentication tag.
 */
[[nodiscard]]
inline std::vector<std::uint8_t> mac(
    const std::string& input_,
    std::span<const std::uint8_t> key_
) {
    return mac<std::string>(input_, key_);
}

/**
 * @brief Verify an HMAC-SHA-512 tag.
 *
 * @tparam T ContiguousByteContainer type for the message.
 *
 * @param tag_ The 64-byte tag to verify.
 * @param input_ The message that was authenticated.
 * @param key_ The 32-byte secret key.
 *
 * @return bool true if the tag is valid, false if not.
 *
 * @throw SodiumLogicError if the key size is invalid.
 */
template<sylvite::concepts::ContiguousByteContainer T>
inline bool verify(
    std::span<const std::uint8_t> tag_,
    const T& input_,
    std::span<const std::uint8_t> key_
) {
    if (tag_.size() != DIGEST_SIZE) return false;
    if (key_.size() != KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid HMAC-SHA-512 key length for verify."
        );
    }
    return crypto_auth_hmacsha512_verify(
        tag_.data(),
        reinterpret_cast<const unsigned char*>(input_.data()),
        input_.size(),
        key_.data()) == 0;
}

/**
 * @brief Streaming HMAC-SHA-512 state.
 *
 * Use for incremental authentication of data that arrives in chunks.
 *
 * @par Usage:
 * @code
 * sylvite::hash::HmacSha512::Stream hasher(key_span);
 * hasher.update(chunk1);
 * hasher.update(chunk2);
 * auto tag = hasher.finalize();
 * @endcode
 */
class Stream final : public sylvite::internal::NonCopyable {
    crypto_auth_hmacsha512_state state_;
    bool finalized_ = false;

public:
    /**
     * @brief Construct a streaming HMAC-SHA-512 hasher.
     *
     * @param key_ The secret key (32 bytes, or empty for null key).
     *
     * @throw sylvite::exceptions::SodiumRuntimeError if initialization fails.
     */
    explicit Stream(std::span<const std::uint8_t> key_ = {}) {
        if (crypto_auth_hmacsha512_init(
                &state_,
                key_.empty() ? nullptr : key_.data(),
                key_.size()) != 0)
        {
            throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-512 stream init failed.");
        }
    }

    /**
     * @brief Add a chunk of data to the HMAC.
     *
     * @tparam T ContiguousByteContainer type.
     * @param data_ The data chunk to incorporate.
     *
     * @return Stream& Reference to this (for chaining).
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    Stream& update(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError(
            "Cannot update a finalized HMAC-SHA-512 stream.");
        if (crypto_auth_hmacsha512_update(
                &state_,
                reinterpret_cast<const unsigned char*>(data_.data()),
                data_.size()) != 0)
        {
            throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-512 stream update failed.");
        }
        return *this;
    }

    /// @brief Overload for std::string.
    Stream& update(const std::string& data_) { return update<std::string>(data_); }

    /**
     * @brief Finalize the HMAC and return the 64-byte tag.
     *
     * @return std::vector<std::uint8_t> The authentication tag.
     */
    [[nodiscard]]
    std::vector<std::uint8_t> finalize() {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError(
            "HMAC-SHA-512 stream already finalized.");
        std::vector<std::uint8_t> out_(DIGEST_SIZE);
        if (crypto_auth_hmacsha512_final(&state_, out_.data()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("HMAC-SHA-512 stream finalize failed.");
        finalized_ = true;
        return out_;
    }

    /// @brief Returns true if finalize() has been called.
    [[nodiscard]] bool is_finalized() const noexcept { return finalized_; }
};

} // namespace HmacSha512

} // namespace sylvite::hash

#endif // SYLVITE_HMAC_HPP
