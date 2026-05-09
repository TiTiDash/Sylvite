/**
 * @file topk.hpp
 * @brief Utility for deriving a public key from a private key.
 *
 * Provides the `FromSkToPk` class with static methods to derive
 * a public key from a Curve25519 or Ed25519 private key.
 *
 * @par Curve25519 derivation:
 *      Uses crypto_scalarmult_base() to compute the public key from
 *      the 32-byte private key using elliptic curve scalar multiplication.
 *
 * @par Ed25519 derivation:
 *      Uses crypto_sign_ed25519_sk_to_pk() to extract the 32-byte
 *      public key from a 64-byte Ed25519 signing key.
 *
 * @par Example:
 *      ```
 *      auto kp = sylvite::asymmetric::crypto_generate_keypair();
 *      auto derived_pk = sylvite::utils::FromSkToPk::crypto(kp.private_key);
 *      assert(derived_pk == kp.public_key); // Always true
 *      ```
 */

#ifndef SYLVITE_TO_PUBLIC_KEY_HPP
#define SYLVITE_TO_PUBLIC_KEY_HPP

#include "../frsdef.hpp"
#include <sodium.h>

namespace sylvite::utils {

/**
 * @brief Utility class for deriving public keys from private keys.
 *
 * Provides static methods to compute the public key corresponding
 * to a given private key for Curve25519 and Ed25519.
 *
 * @par Thread safety:
 *      These functions are reentrant and thread-safe. Multiple threads
 *      can derive public keys simultaneously.
 */
class FromSkToPk final {
    public:
    /**
     * @brief Derive a Curve25519 public key from a 32-byte private key.
     *
     * @param sk_ The 32-byte Curve25519 private key.
     * @return sylvite::types::PublicKey The corresponding 32-byte public key.
     *
     * @throw SodiumRuntimeError if derivation fails (should not happen
     *        with a valid 32-byte key).
     *
     * @par Algorithm:
     *      Uses crypto_scalarmult_base() which computes:
     *      P = [scalar]G
     *      where G is the Curve25519 base point and scalar is the
     *      private key as a little-endian 255-bit integer.
     *
     * @par Example:
     *      ```
     *      auto kp = sylvite::asymmetric::crypto_generate_keypair();
     *      auto pk = sylvite::utils::FromSkToPk::crypto(kp.private_key);
     *      ```
     */
    [[nodiscard]]
    static sylvite::types::PublicKey crypto(const sylvite::types::PrivateKey& sk_) {
        sylvite::types::PublicKey pk_;
        int res_ = crypto_scalarmult_base(pk_.data(), sk_.data());
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Could not derive public key from the provided private key.");
        return pk_;
    }

    /**
     * @brief Derive an Ed25519 public key from a 64-byte Ed25519 signing key.
     *
     * @param sk_ The 64-byte Ed25519 private key.
     * @return sylvite::types::PublicKey The corresponding 32-byte public key.
     *
     * @throw SodiumRuntimeError if derivation fails.
     *
     * @par Algorithm:
     *      Uses crypto_sign_ed25519_sk_to_pk() to extract the public
     *      key from the expanded Ed25519 signing key. The 64-byte key
     *      contains both the 32-byte scalar (first 32 bytes) and the
     *      32-byte prefix (used for deterministic nonce generation).
     *
     * @par Note:
     *      Ed25519 signing keys are 64 bytes because they store both
     *      the scalar and the hash-based nonce prefix. The public key
     *      is derived from the scalar portion.
     *
     * @par Example:
     *      ```
     *      auto kp = sylvite::asymmetric::sign_generate_keypair();
     *      auto pk = sylvite::utils::FromSkToPk::sign(kp.private_key);
     *      ```
     */
    [[nodiscard]]
    static sylvite::types::PublicKey sign(const sylvite::types::PrivateKey& sk_) {
        sylvite::types::PublicKey pk_;
        int res_ = crypto_sign_ed25519_sk_to_pk(pk_.data(), sk_.data());
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Could not derive public key from the provided private key.");
        return pk_;
    }
};

} // namespace sylvite::utils

#endif
