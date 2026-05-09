/**
 * @file salt.hpp
 * @brief Salt type for password-based key derivation (Argon2ID).
 *
 * Represents a cryptographic salt — a random value used as input to
 * password-based key derivation functions (KDFs) like Argon2ID.
 *
 * Salts are NOT secret — they can be stored alongside encrypted data
 * and transmitted in the clear. Their purpose is to ensure that
 * deriving a key from the same password with the same salt always
 * produces the same key, while using different salts for the same
 * password produces different keys.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T reuse a salt** — Each password-based key derivation must use a
 *    unique, random salt. Reusing salts allows attackers to precompute hashes
 *    for common passwords.
 * - **DON'T use predictable salts** — Always generate salts with random_generate().
 *    Predictable salts (like usernames, timestamps, or counters) defeat the purpose.
 * - **DON'T use salts that are too short** — For Argon2ID, use at least 16 bytes.
 *    Shorter salts reduce the effectiveness against rainbow table attacks.
 * - **DON'T treat salts as secret** — Salts don't need to be kept secret. Store
 *    them alongside the ciphertext. The security comes from uniqueness, not secrecy.
 *
 * @par Why salts matter:
 *      Without a salt, an attacker could pre-compute hashes of common
 *      passwords (rainbow tables). With a unique salt per derivation,
 *      each password guess requires recomputing the KDF, making
 *      pre-computation attacks infeasible.
 *
 * @par Size:
 *      For Argon2ID, the default salt size is 16 bytes
 *      (crypto_pwhash_argon2id_SALTBYTES). Other algorithms may
 *      require different sizes.
 *
 * @par Example:
 *      ```
 *      sylvite::types::Salt salt; // 16 bytes by default
 *      salt.random_generate();
 *
 *      auto key = sylvite::kdf::Argon2ID_derive_key(
 *          password, salt, 32, sylvite::kdf::Profile::Moderate
 *      );
 *      // salt can now be stored alongside the ciphertext
 *      ```
 */

#ifndef SYLVITE_SALT_TYPE_HPP
#define SYLVITE_SALT_TYPE_HPP

#include <exception>
#include <utility>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <ranges>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"

namespace sylvite::types {

/**
 * @brief A salt for password-based key derivation.
 *
 * A non-copyable buffer holding a cryptographic salt. Unlike keys,
 * salts do not need secure memory (they're not secret), but use the
 * same Base class interface for consistency.
 *
 * @par Default construction:
 *      Salt() creates a salt of size crypto_pwhash_argon2id_SALTBYTES (16 bytes).
 *      Use Salt(n) to create a salt of a specific size.
 *
 * @par Construction from existing data:
 *      Can be constructed from a span or vector of bytes. The salt
 *      is simply copied — no secure memory needed.
 *
 * @par Random generation:
 *      Always generate salts using random_generate() to ensure
 *      cryptographically random content. Never use predictable values.
 *
 * @par Thread safety:
 *      Salt objects are not thread-safe. Each derivation should use its
 *      own Salt instance, or use proper synchronization.
 *
 * @par Example:
 *      ```
 *      // Create a 16-byte salt for Argon2ID
 *      sylvite::types::Salt salt;
 *      salt.random_generate();
 *
 *      // Or create with specific size for other KDFs
 *      sylvite::types::Salt salt(32);
 *      salt.random_generate();
 *      ```
 */
class Salt final : public sylvite::internal::Base<std::uint8_t>, public sylvite::internal::NonCopyable {
    using B_ = Base<std::uint8_t>;

    public:
    /**
     * @brief Default constructor — creates a 16-byte salt (Argon2ID default).
     *
     * Allocates 16 bytes of uninitialized memory. Call random_generate()
     * to fill with random data.
     */
    Salt() : B_(crypto_pwhash_argon2id_SALTBYTES) {}

    /**
     * @brief Construct a salt with a specific size.
     * @param sz_ The size in bytes.
     */
    Salt(std::size_t sz_) : B_(sz_) {}

    /**
     * @brief Construct a salt by moving an existing vector.
     * @param v_ The vector containing the salt data.
     */
    Salt(std::vector<std::uint8_t>&& v_) : B_(std::move(v_)) {}

    /**
     * @brief Construct a salt from a byte span.
     * @param s_span_ The span containing the salt data.
     */
    Salt(std::span<const std::uint8_t> s_span_) : B_(s_span_) {}

    /**
     * @brief Construct a salt from any Container with byte-like values.
     * @tparam T A Container type with data() and size() methods.
     * @param c_ The container to copy from.
     *
     * Copies the container's data into the salt. The container's
     * data is not modified or wiped.
     */
    template<sylvite::concepts::Container T>
    Salt(T& c_) {
        vec_.resize(c_.size());
        std::memcpy(vec_.data(), c_.data(), c_.size());
    }

    /**
     * @brief Resize the salt and fill with random bytes.
     * @param n_ The new size in bytes.
     *
     * Resizes the salt to n_ bytes and fills it with random data.
     */
    void random_generate(std::size_t n_) {
        vec_.resize(n_);
        if (n_ > 0)
        randombytes_buf(vec_.data(), vec_.size());
    }

    /**
     * @brief Re-randomize the existing salt buffer.
     *
     * Fills the existing buffer (previously allocated) with new
     * random bytes. The salt must already have a size > 0.
     *
     * @note This is noexcept as long as the existing allocation is valid.
     */
    void random_generate() noexcept {
        if (vec_.size() > 0)
        randombytes_buf(vec_.data(), vec_.size());
    }
};

} // namespace sylvite::types

#endif
