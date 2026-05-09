/**
 * @file privatekey.hpp
 * @brief Private key type for asymmetric cryptography.
 *
 * Represents a private (secret) key for asymmetric crypto operations.
 * Private keys are:
 * - Non-copyable (move-only to prevent accidental duplication)
 * - Stored in secure memory (s_alloc — locked, zeroed on deallocation)
 * - Sized according to algorithm: 32 bytes (Curve25519), 64 bytes (Ed25519), 2,400 bytes (ML-KEM-768)
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T copy private keys** — PrivateKey is non-copyable for a reason.
 *    Copying sensitive key material doubles attack surface. Use move semantics.
 * - **DON'T log or serialize private keys** — Even encrypted keys in logs are a risk.
 *    Store keys in a secure key management system, not in configuration files.
 * - **DON'T use private keys of the wrong size** — Curve25519 needs 32 bytes,
 *    Ed25519 needs 64 bytes, ML-KEM-768 needs 2,400 bytes. Using the wrong size
 *    will cause cryptographic operations to fail.
 * - **DON'T forget to wipe private keys** — Call wipe() after use to minimize
 *    the window of exposure, even though s_alloc zeros memory on deallocation.
 *
 * @par Security:
 *      Private keys are highly sensitive. Always:
 *      - Store them in secure memory (s_alloc provides this)
 *      - Call wipe() when no longer needed
 *      - Never share them
 *      - Never log or serialize them unnecessarily
 *
 * @par Size by algorithm:
 * - Curve25519 (Box): 32 bytes (crypto_box_SECRETKEYBYTES)
 * - Ed25519 (Sign): 64 bytes (crypto_sign_SECRETKEYBYTES)
 * - ML-KEM-768: 2,400 bytes (crypto_kem_mlkem768_SECRETKEYBYTES)
 *
 * @par Key generation:
 *      Private keys are typically generated via:
 *      - `sylvite::asymmetric::crypto_generate_keypair()` — Curve25519
 *      - `sylvite::asymmetric::sign_generate_keypair()` — Ed25519
 *      - `sylvite::kem::MlKem768::generate_keypair()` — ML-KEM-768
 *
 * @par Example:
 *      ```
 *      auto kp = sylvite::asymmetric::crypto_generate_keypair();
 *      // kp.private_key is the secret key - handle with care!
 *      auto ct = sylvite::asymmetric::SealedBox::seal(data, kp.public_key);
 *      auto pt = sylvite::asymmetric::SealedBox::open(ct, kp.private_key);
 *      kp.private_key.wipe(); // wipe when done
 *      ```
 */

#ifndef SYLVITE_PRIVATE_KEY_HPP
#define SYLVITE_PRIVATE_KEY_HPP

#include <vector>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"

namespace sylvite::types {

/**
 * @brief A private (secret) key for asymmetric cryptography.
 *
 * Private keys are non-copyable and use secure memory allocation (s_alloc)
 * to ensure they are locked in RAM and wiped on deallocation.
 *
 * @par Construction:
 *      Private keys should be created via keypair generation functions
 *      or the static factory methods (PrivateKey::crypto(), PrivateKey::sign()).
 *      Direct construction is restricted to friend functions.
 *
 * @par Static factories:
 *      - `PrivateKey::crypto()` — creates a 32-byte key for Curve25519 Box
 *      - `PrivateKey::sign()` — creates a 64-byte key for Ed25519 signing
 *
 * @par Move semantics:
 *      Move construction and move assignment ARE allowed, important for
 *      returning keys from functions without copying.
 *
 * @par Thread safety:
 *      PrivateKey is not thread-safe. Each key should be accessed from
 *      one thread or protected by synchronization.
 *
 * @par Example:
 *      ```
 *      auto kp = sylvite::asymmetric::crypto_generate_keypair();
 *      auto sk = std::move(kp.private_key); // Move into a named variable
 *      // use sk...
 *      sk.wipe(); // explicitly wipe when done
 *      ```
 */
class PrivateKey final : public sylvite::internal::Base<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>> {
    using B_ = sylvite::internal::Base<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>>;

    /// @brief Construct with a specific size (friend functions only).
    PrivateKey(std::size_t sz_) : B_(sz_) {}
    /// @brief Default constructor (friend functions only).
    PrivateKey() : B_() {}

    /// @brief Resize the key buffer (friend functions only).
    void resize(std::size_t n_) {
        this->vec_.resize(n_);
    }

    public:
    /**
     * @brief Construct a Curve25519 private key from a 32-byte span.
     * @param view_ Span containing exactly 32 bytes (crypto_box_SECRETKEYBYTES).
     *
     * @throw SodiumLogicError if the span is not exactly 32 bytes.
     */
    explicit PrivateKey(std::span<const std::uint8_t, crypto_box_SECRETKEYBYTES> view_) : B_(view_) {}

    /**
     * @brief Construct an Ed25519 private key from a 64-byte span.
     * @param view_ Span containing exactly 64 bytes (crypto_sign_SECRETKEYBYTES).
     *
     * @throw SodiumLogicError if the span is not exactly 64 bytes.
     */
    explicit PrivateKey(std::span<const std::uint8_t, crypto_sign_SECRETKEYBYTES> view_) : B_(view_) {}

    /**
     * @brief Construct a ML-KEM-768 private key from a 2,400-byte span.
     * @param view_ Span containing exactly 2,400 bytes.
     *
     * @throw SodiumLogicError if the span is not exactly 2,400 bytes.
     */
    explicit PrivateKey(std::span<const std::uint8_t, crypto_kem_mlkem768_SECRETKEYBYTES> view_) : B_(view_) {}

    /**
     * @brief Construct a private key by moving a secure vector.
     * @param v_ A vector allocated with s_alloc containing key data.
     *
     * Validates that the vector size is either 32 bytes (Curve25519)
     * or 64 bytes (Ed25519).
     *
     * @throw SodiumLogicError if the vector size is not 32 or 64 bytes.
     */
    explicit PrivateKey(std::vector<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>>&& v_) {
        if (v_.size() == crypto_sign_SECRETKEYBYTES) this->vec_ = std::move(v_);
        else if (v_.size() == crypto_box_SECRETKEYBYTES) this->vec_ = std::move(v_);
        else throw sylvite::exceptions::SodiumLogicError("The vector size must be 32 bytes or 64 bytes.");
    }

    // Allow key generation functions to use private constructors
    friend class sylvite::kem::KeyPair;
    friend sylvite::kem::KeyPair sylvite::kem::XWing::generate_keypair();
    friend sylvite::kem::KeyPair sylvite::kem::MlKem768::generate_keypair();

    /**
     * @brief Factory: create a 32-byte Curve25519 private key.
     * @return PrivateKey A 32-byte key allocated with secure memory.
     *
     * @par Use case:
     *      Used by crypto_box keypair generation to create a key
     *      sized appropriately for Curve25519 operations.
     */
    static PrivateKey crypto() {
        return PrivateKey(32);
    }

    /**
     * @brief Factory: create a 64-byte Ed25519 private key.
     * @return PrivateKey A 64-byte key allocated with secure memory.
     *
     * @par Use case:
     *      Used by Ed25519 signing keypair generation to create a key
     *      sized appropriately for Ed25519 operations.
     */
    static PrivateKey sign() {
        return PrivateKey(64);
    }
};

} // namespace sylvite::types

#endif
