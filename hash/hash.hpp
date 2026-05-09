/**
 * @file hash.hpp
 * @brief Cryptographic hash functions: SHA2, SHA3, and BLAKE2b.
 *
 * **SHA-256 / SHA-512**: Standard SHA-2 family hash functions.
 * **SHA3-256 / SHA3-512**: SHA-3 family based on Keccak sponge.
 * **BLAKE2b**: Fast hash for software environments.
 *
 * @par Security warnings:
 * - DON'T use SHA-2 for MACs (vulnerable to length-extension)
 * - DON'T use SHA-2 for password hashing (too fast)
 * - DON'T use hash output as a key (use HKDF or Argon2ID)
 * - BLAKE2b keyed mode != HMAC (use sylvite::hash::HmacSha256 for authentication)
 */


#ifndef SYLVITE_HASH_HPP
#define SYLVITE_HASH_HPP

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
#include "../utils/base64.hpp"

namespace sylvite::hash {

namespace Blake2b {

/**
 * @brief Compute a BLAKE2b hash of the input data.
 *
 * @tparam T ContiguousByteContainer type for the input.
 *
 * @param input_ The data to hash.
 * @param out_len_ Desired output length in bytes (default 32).
 * @param key_ Optional key for keyed hashing (optional).
 *
 * @return std::vector<std::uint8_t> The hash digest.
 *
 * @throw SodiumLogicError if parameters are invalid.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> digest(
    const T& input_,
    std::size_t out_len_ = crypto_generichash_BYTES,
    std::span<const std::uint8_t> key_ = {}
) {
    if (out_len_ < crypto_generichash_BYTES_MIN || out_len_ > crypto_generichash_BYTES_MAX) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid BLAKE2b output length. Must be between " +
            std::to_string(crypto_generichash_BYTES_MIN) + " and " +
            std::to_string(crypto_generichash_BYTES_MAX) + " bytes, got " +
            std::to_string(out_len_)
        );
    }
    if (!key_.empty() &&
        (key_.size() < crypto_generichash_KEYBYTES_MIN ||
         key_.size() > crypto_generichash_KEYBYTES_MAX))
    {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid BLAKE2b key length. Must be between " +
            std::to_string(crypto_generichash_KEYBYTES_MIN) + " and " +
            std::to_string(crypto_generichash_KEYBYTES_MAX) + " bytes, got " +
            std::to_string(key_.size())
        );
    }

    std::vector<std::uint8_t> out_(out_len_);

    int res_ = crypto_generichash(
        out_.data(), out_len_,
        reinterpret_cast<const unsigned char*>(input_.data()), input_.size(),
        key_.empty() ? nullptr : key_.data(),
        key_.size()
    );

    if (res_ != 0) {
        throw sylvite::exceptions::SodiumRuntimeError("BLAKE2b hash failed.");
    }

    return out_;
}

/**
 * @brief Compute a BLAKE2b hash and return it as a lowercase hex string.
 *
 * @tparam T ContiguousByteContainer type for the input.
 *
 * @param input_ The data to hash.
 * @param out_len_ Desired output length (default 32).
 * @param key_ Optional keyed hashing key.
 *
 * @return std::string Lowercase hexadecimal representation of the hash.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::string hexdigest(
    const T& input_,
    std::size_t out_len_ = crypto_generichash_BYTES,
    std::span<const std::uint8_t> key_ = {}
) {
    return sylvite::utils::Hex::encode(digest(input_, out_len_, key_));
}

/**
 * @brief Streaming BLAKE2b hash state.
 *
 * Use for hashing data in chunks or when data doesn't fit in memory.
 */
class Stream final : public sylvite::internal::NonCopyable {
    crypto_generichash_state state_;
    bool finalized_ = false;

public:
    /**
     * @brief Construct a streaming BLAKE2b hasher.
     *
     * @param out_len_ Desired output length in bytes (default 32).
     * @param key_ Optional key for keyed hashing.
     */
    explicit Stream(
        std::size_t out_len_ = crypto_generichash_BYTES,
        std::span<const std::uint8_t> key_ = {}
    ) : out_len_(out_len_)
    {
        if (out_len_ < crypto_generichash_BYTES_MIN || out_len_ > crypto_generichash_BYTES_MAX) {
            throw sylvite::exceptions::SodiumLogicError(
                "Invalid BLAKE2b output length: " + std::to_string(out_len_)
            );
        }

        int res_ = crypto_generichash_init(
            &state_,
            key_.empty() ? nullptr : key_.data(),
            key_.size(),
            out_len_
        );
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("BLAKE2b stream init failed.");
    }

    /**
     * @brief Add a data chunk to the hash.
     *
     * @tparam T ContiguousByteContainer type.
     * @param data_ The data chunk.
     * @return Stream& For chaining.
     *
     * @throw SodiumLogicError if the stream was already finalized.
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    Stream& update(const T& data_) {
        if (finalized_) {
            throw sylvite::exceptions::SodiumLogicError(
                "Cannot update a finalized BLAKE2b stream."
            );
        }
        int res_ = crypto_generichash_update(
            &state_,
            reinterpret_cast<const unsigned char*>(data_.data()),
            data_.size()
        );
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("BLAKE2b stream update failed.");
        return *this;
    }

    /// @brief Overload for std::string.
    Stream& update(const std::string& data_) {
        return update<std::string>(data_);
    }

    /**
     * @brief Finalize the hash and return the digest.
     *
     * @return std::vector<std::uint8_t> The hash digest.
     *
     * @throw SodiumLogicError if the stream was already finalized.
     */
    [[nodiscard]]
    std::vector<std::uint8_t> finalize() {
        if (finalized_) {
            throw sylvite::exceptions::SodiumLogicError(
                "BLAKE2b stream already finalized."
            );
        }
        std::vector<std::uint8_t> out_(out_len_);
        int res_ = crypto_generichash_final(&state_, out_.data(), out_len_);
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("BLAKE2b stream finalize failed.");
        finalized_ = true;
        return out_;
    }

    /// @brief Returns true if finalize() has been called.
    [[nodiscard]] bool is_finalized() const noexcept { return finalized_; }

private:
    std::size_t out_len_;  ///< Desired output length (stored for finalize).
};

} // namespace Blake2b

namespace Sha256 {

/// @brief Output size of SHA-256 in bytes (32 bytes).
static constexpr std::size_t DIGEST_SIZE = crypto_hash_sha256_BYTES;

/**
 * @brief Compute a SHA-256 hash of the input data.
 *
 * @tparam T ContiguousByteContainer type.
 * @param input_ The data to hash.
 * @return std::vector<std::uint8_t> The 32-byte hash digest.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> digest(const T& input_) {
    std::vector<std::uint8_t> out_(DIGEST_SIZE);
    int res_ = crypto_hash_sha256(
        out_.data(),
        reinterpret_cast<const unsigned char*>(input_.data()),
        input_.size()
    );
    if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("SHA-256 hash failed.");
    return out_;
}

/**
 * @brief Compute a SHA-256 hash and return it as a hex string.
 *
 * @tparam T ContiguousByteContainer type.
 * @param input_ The data to hash.
 * @return std::string Hexadecimal representation of the hash.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::string hexdigest(const T& input_) {
    return sylvite::utils::Hex::encode(digest(input_));
}

/**
 * @brief Streaming SHA-256 hash state.
 *
 * @par Usage:
 * @code
 * sylvite::hash::Sha256::Stream hasher;
 * hasher.update(data_chunk);
 * auto digest = hasher.finalize();
 * @endcode
 */
class Stream final : public sylvite::internal::NonCopyable {
    crypto_hash_sha256_state state_;
    bool finalized_ = false;

public:
    Stream() {
        if (crypto_hash_sha256_init(&state_) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA-256 stream init failed.");
    }

    /**
     * @brief Add a data chunk to the hash.
     *
     * @tparam T ContiguousByteContainer type.
     * @param data_ The data chunk.
     * @return Stream& For chaining.
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    Stream& update(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError("Cannot update a finalized SHA-256 stream.");
        if (crypto_hash_sha256_update(
                &state_,
                reinterpret_cast<const unsigned char*>(data_.data()),
                data_.size()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA-256 stream update failed.");
        return *this;
    }

    /// @brief Overload for std::string.
    Stream& update(const std::string& data_) { return update<std::string>(data_); }

    /**
     * @brief Finalize the hash and return the digest.
     *
     * @return std::vector<std::uint8_t> The SHA-256 digest.
     */
    [[nodiscard]]
    std::vector<std::uint8_t> finalize() {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError("SHA-256 stream already finalized.");
        std::vector<std::uint8_t> out_(DIGEST_SIZE);
        if (crypto_hash_sha256_final(&state_, out_.data()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA-256 stream finalize failed.");
        finalized_ = true;
        return out_;
    }

    /// @brief Returns true if finalize() has been called.
    [[nodiscard]] bool is_finalized() const noexcept { return finalized_; }
};

} // namespace Sha256

namespace Sha512 {

/// @brief Output size of SHA-512 in bytes (64 bytes).
static constexpr std::size_t DIGEST_SIZE = crypto_hash_sha512_BYTES;

/**
 * @brief Compute a SHA-512 hash of the input data.
 *
 * @tparam T ContiguousByteContainer type.
 * @param input_ The data to hash.
 * @return std::vector<std::uint8_t> The 64-byte hash digest.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> digest(const T& input_) {
    std::vector<std::uint8_t> out_(DIGEST_SIZE);
    int res_ = crypto_hash_sha512(
        out_.data(),
        reinterpret_cast<const unsigned char*>(input_.data()),
        input_.size()
    );
    if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("SHA-512 hash failed.");
    return out_;
}

/**
 * @brief Compute a SHA-512 hash and return it as a hex string.
 *
 * @tparam T ContiguousByteContainer type.
 * @param input_ The data to hash.
 * @return std::string Hexadecimal representation of the hash.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::string hexdigest(const T& input_) {
    return sylvite::utils::Hex::encode(digest(input_));
}

/**
 * @brief Streaming SHA-512 hash state.
 */
class Stream final : public sylvite::internal::NonCopyable {
    crypto_hash_sha512_state state_;
    bool finalized_ = false;

public:
    Stream() {
        if (crypto_hash_sha512_init(&state_) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA-512 stream init failed.");
    }

    /**
     * @brief Add a data chunk to the hash.
     *
     * @tparam T ContiguousByteContainer type.
     * @param data_ The data chunk.
     * @return Stream& For chaining.
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    Stream& update(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError("Cannot update a finalized SHA-512 stream.");
        if (crypto_hash_sha512_update(
                &state_,
                reinterpret_cast<const unsigned char*>(data_.data()),
                data_.size()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA-512 stream update failed.");
        return *this;
    }

    Stream& update(const std::string& data_) { return update<std::string>(data_); }

    /**
     * @brief Finalize the hash and return the digest.
     *
     * @return std::vector<std::uint8_t> The SHA-512 digest.
     */
    [[nodiscard]]
    std::vector<std::uint8_t> finalize() {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError("SHA-512 stream already finalized.");
        std::vector<std::uint8_t> out_(DIGEST_SIZE);
        if (crypto_hash_sha512_final(&state_, out_.data()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA-512 stream finalize failed.");
        finalized_ = true;
        return out_;
    }

    /// @brief Returns true if finalize() has been called.
    [[nodiscard]] bool is_finalized() const noexcept { return finalized_; }
};

} // namespace Sha512

namespace Sha3_256 {

static constexpr std::size_t DIGEST_SIZE = crypto_hash_sha3256_BYTES;

/**
 * @brief Compute a SHA3-256 hash of the input data.
 *
 * @tparam T ContiguousByteContainer type.
 * @param input_ The data to hash.
 * @return std::vector<std::uint8_t> The 32-byte hash digest.
 *
 * @par Note: SHA3-256 is NOT vulnerable to length-extension attacks.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> digest(const T& input_) {
    std::vector<std::uint8_t> out_(DIGEST_SIZE);
    if (crypto_hash_sha3256(
            out_.data(),
            reinterpret_cast<const unsigned char*>(input_.data()),
            input_.size()) != 0)
    {
        throw sylvite::exceptions::SodiumRuntimeError("SHA3-256 hash failed.");
    }
    return out_;
}

/**
 * @brief Compute a SHA3-256 hash and return it as a hex string.
 *
 * @tparam T ContiguousByteContainer type.
 * @param input_ The data to hash.
 * @return std::string Hexadecimal representation.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::string hexdigest(const T& input_) {
    return sylvite::utils::Hex::encode(digest(input_));
}

class Stream final : public sylvite::internal::NonCopyable {
    crypto_hash_sha3256_state state_;
    bool finalized_ = false;

public:
    Stream() {
        if (crypto_hash_sha3256_init(&state_) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA3-256 stream init failed.");
    }

    /**
     * @brief Add a data chunk to the hash.
     *
     * @tparam T ContiguousByteContainer type.
     * @param data_ The data chunk.
     * @return Stream& For chaining.
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    Stream& update(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError(
            "Cannot update a finalized SHA3-256 stream.");
        if (crypto_hash_sha3256_update(
                &state_,
                reinterpret_cast<const unsigned char*>(data_.data()),
                data_.size()) != 0)
        {
            throw sylvite::exceptions::SodiumRuntimeError("SHA3-256 stream update failed.");
        }
        return *this;
    }

    /// @brief Overload for std::string.
    Stream& update(const std::string& data_) { return update<std::string>(data_); }

    /**
     * @brief Finalize the hash and return the digest.
     *
     * @return std::vector<std::uint8_t> The SHA3-256 digest.
     */
    [[nodiscard]]
    std::vector<std::uint8_t> finalize() {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError("SHA3-256 stream already finalized.");
        std::vector<std::uint8_t> out_(DIGEST_SIZE);
        if (crypto_hash_sha3256_final(&state_, out_.data()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA3-256 stream finalize failed.");
        finalized_ = true;
        return out_;
    }

    /// @brief Returns true if finalize() has been called.
    [[nodiscard]] bool is_finalized() const noexcept { return finalized_; }
};

} // namespace Sha3_256

namespace Sha3_512 {

/// @brief Output size of SHA3-512 in bytes (64 bytes).
static constexpr std::size_t DIGEST_SIZE = crypto_hash_sha3512_BYTES;

/**
 * @brief Compute a SHA3-512 hash of the input data.
 *
 * @tparam T ContiguousByteContainer type.
 *
 * @param input_ The data to hash.
 *
 * @return std::vector<std::uint8_t> The 64-byte hash digest.
 *
 * @par Note:
 *      SHA3-512 is NOT vulnerable to length-extension attacks
 *      (unlike SHA-512).
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> digest(const T& input_) {
    std::vector<std::uint8_t> out_(DIGEST_SIZE);
    if (crypto_hash_sha3512(
            out_.data(),
            reinterpret_cast<const unsigned char*>(input_.data()),
            input_.size()) != 0)
    {
        throw sylvite::exceptions::SodiumRuntimeError("SHA3-512 hash failed.");
    }
    return out_;
}

/**
 * @brief Compute a SHA3-512 hash and return it as a hex string.
 *
 * @tparam T ContiguousByteContainer type.
 * @param input_ The data to hash.
 * @return std::string Hexadecimal representation.
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::string hexdigest(const T& input_) {
    return sylvite::utils::Hex::encode(digest(input_));
}

class Stream final : public sylvite::internal::NonCopyable {
    crypto_hash_sha3512_state state_;
    bool finalized_ = false;

public:
    Stream() {
        if (crypto_hash_sha3512_init(&state_) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA3-512 stream init failed.");
    }

    /**
     * @brief Add a data chunk to the hash.
     *
     * @tparam T ContiguousByteContainer type.
     * @param data_ The data chunk.
     * @return Stream& For chaining.
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    Stream& update(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError(
            "Cannot update a finalized SHA3-512 stream.");
        if (crypto_hash_sha3512_update(
                &state_,
                reinterpret_cast<const unsigned char*>(data_.data()),
                data_.size()) != 0)
        {
            throw sylvite::exceptions::SodiumRuntimeError("SHA3-512 stream update failed.");
        }
        return *this;
    }

    /// @brief Overload for std::string.
    Stream& update(const std::string& data_) { return update<std::string>(data_); }

    /**
     * @brief Finalize the hash and return the digest.
     *
     * @return std::vector<std::uint8_t> The SHA3-512 digest.
     */
    [[nodiscard]]
    std::vector<std::uint8_t> finalize() {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError("SHA3-512 stream already finalized.");
        std::vector<std::uint8_t> out_(DIGEST_SIZE);
        if (crypto_hash_sha3512_final(&state_, out_.data()) != 0)
            throw sylvite::exceptions::SodiumRuntimeError("SHA3-512 stream finalize failed.");
        finalized_ = true;
        return out_;
    }

    bool is_finalized() const noexcept { return finalized_; }
};

} // namespace Sha3_512

} // namespace sylvite::hash

#endif // SYLVITE_HASH_HPP