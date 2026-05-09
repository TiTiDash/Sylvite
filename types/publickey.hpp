/**
 * @file publickey.hpp
 * @brief Public key type for asymmetric cryptography.
 *
 * Represents a public key for use with asymmetric crypto operations:
 * - Curve25519 (crypto_box, crypto_box_seal)
 * - Ed25519 (crypto_sign)
 * - ML-KEM-768 (ML-KEM key encapsulation)
 *
 * Public keys are NOT sensitive (they can be shared freely), but use
 * secure memory for consistency with the private key interface and to
 * allow passing to APIs that need mutable access.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T assume a public key is authentic** — Always verify public keys
 *    through a trusted channel before using them for encryption or verification.
 *    An attacker could substitute their own public key.
 * - **DON'T use the wrong public key size** — Curve25519/Ed25519 need 32 bytes,
 *    ML-KEM-768 needs 1,184 bytes. Mismatched sizes indicate wrong key type.
 * - **DON'T reuse Ed25519 public keys as Curve25519 keys** — They use different
 *    curves and are not interchangeable. Use separate key pairs for signing
 *    and encryption.
 *
 * @par Size by algorithm:
 * - Curve25519: 32 bytes
 * - Ed25519: 32 bytes
 * - ML-KEM-768: 1,184 bytes
 *
 * @par Example:
 * @code
 * auto kp = sylvite::asymmetric::crypto_generate_keypair();
 * // kp.public_key can be shared with anyone
 * // kp.private_key must be kept secret
 * @endcode
 */

#ifndef SYLVITE_PUBLIC_KEY_HPP
#define SYLVITE_PUBLIC_KEY_HPP

#include <vector>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"

namespace sylvite::types {

/**
 * @brief A public key for asymmetric cryptography.
 *
 * Public keys in Sylvite are non-copyable (move-only) and use secure
 * memory allocation (s_alloc) for consistency, even though public key
 * material is not secret. This allows the same type to work with both
 * regular and secret-bearing key operations.
 *
 * @par Construction:
 *      Public keys are typically generated via keypair generation functions:
 *      - `sylvite::asymmetric::crypto_generate_keypair()` — Curve25519
 *      - `sylvite::asymmetric::sign_generate_keypair()` — Ed25519
 *      - `sylvite::kem::MlKem768::generate_keypair()` — ML-KEM-768
 *
 *      Or derived from a private key using:
 *      - `sylvite::utils::FromSkToPk::crypto(sk)` — Curve25519
 *      - `sylvite::utils::FromSkToPk::sign(sk)` — Ed25519
 *
 * @par Thread safety:
 *      PublicKey is not thread-safe for concurrent modification.
 *      Multiple threads can read the same PublicKey simultaneously.
 */
class PublicKey final: public sylvite::internal::Base<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>> {
    using B_ = sylvite::internal::Base<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>>;

    /// @brief Resize operation — used by friend key generation functions.
    void resize(std::size_t n_) {
        this->vec_.resize(n_);
    }

    public:
    /**
     * @brief Construct a PublicKey from a 32-byte span (Ed25519 public key).
     * @param view_ Span containing exactly 32 bytes.
     */
    explicit PublicKey(std::span<std::uint8_t, crypto_sign_PUBLICKEYBYTES> view_) : B_(view_) {}

    /**
     * @brief Construct a PublicKey from a ML-KEM-768 public key span.
     * @param view_ Span containing exactly 1,184 bytes.
     */
    explicit PublicKey(std::span<std::uint8_t, crypto_kem_mlkem768_PUBLICKEYBYTES> view_) : B_(view_) {}

    /// @brief Default constructor — creates a 32-byte (Curve25519-sized) public key.
    explicit PublicKey() : B_(32) {}

    /**
     * @brief Construct a PublicKey with a specific size.
     * @param size_ The size in bytes.
     *
     * Use this when you need to pre-allocate space before population
     * by a key generation function.
     */
    explicit PublicKey(std::size_t size_) : B_(size_) {}

    // Allow key generation functions to resize the key
    friend sylvite::kem::KeyPair sylvite::kem::XWing::generate_keypair();
    friend sylvite::kem::KeyPair sylvite::kem::MlKem768::generate_keypair();
};

} // namespace sylvite::types

#endif
