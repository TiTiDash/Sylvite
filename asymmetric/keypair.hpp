/**
 * @file keypair.hpp
 * @brief Key pair generation for asymmetric cryptography.
 *
 * Provides key pair generation for:
 * - Curve25519 Box (crypto_box_keypair)
 * - Ed25519 signing (crypto_sign_ed25519_keypair)
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use the same key pair for both signing and encryption** — Curve25519
 *    (encryption) and Ed25519 (signing) use different curves. Using one key pair
 *    for both purposes is cryptographically unsound and can lead to key recovery.
 * - **DON'T store key pairs in plaintext** — Private keys must be protected.
 *    Store them encrypted with a password-derived key or in a secure enclave.
 * - **DON'T share private keys** — The private key must remain secret. Only the
 *    public key should be distributed.
 * - **DON'T forget to wipe private keys** — Call wipe() on the private key when
 *    the keypair is no longer needed to minimize exposure window.
 *
 * @par Curve25519 vs Ed25519 key pairs:
 *      Curve25519 key pairs are 32 bytes each and are used for
 *      encryption (Box, SealedBox).
 *      Ed25519 key pairs are 64 bytes (private) and 32 bytes (public)
 *      and are used for digital signatures (sign/verify).
 *
 * @par Example:
 * @code
 * // Curve25519 key pair for encryption
 * auto box_kp = sylvite::asymmetric::crypto_generate_keypair();
 *
 * // Ed25519 key pair for signing
 * auto sign_kp = sylvite::asymmetric::sign_generate_keypair();
 * @endcode
 */

#ifndef SYLVITE_KEYPAIR_HPP
#define SYLVITE_KEYPAIR_HPP

#include <utility>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../types/publickey.hpp"
#include "../types/privatekey.hpp"

namespace sylvite::asymmetric {

/**
 * @brief A public/private key pair for asymmetric cryptography.
 *
 * Holds both the public key and private key. The private key is
 * sensitive and should be protected.
 *
 * @par Construction:
 *      KeyPair objects are typically created by the generation functions:
 *      - crypto_generate_keypair() — creates a Curve25519 key pair
 *      - sign_generate_keypair() — creates an Ed25519 key pair
 */
struct KeyPair {
    sylvite::types::PublicKey public_key;   ///< The public key (can be shared freely).
    sylvite::types::PrivateKey private_key; ///< The private key (keep secret).
};

/**
 * @brief Generate a Curve25519 key pair for Box/SealedBox encryption.
 *
 * @return KeyPair with a 32-byte public key and 32-byte private key.
 *
 * @par Security:
 *      The key pair is generated using libsodium's CSPRNG.
 *      Both keys are allocated with secure memory (s_alloc).
 *
 * @par Key sizes:
 *      - Public key: 32 bytes (crypto_box_PUBLICKEYBYTES)
 *      - Private key: 32 bytes (crypto_box_SECRETKEYBYTES)
 *
 * @par Example:
 * @code
 * auto kp = sylvite::asymmetric::crypto_generate_keypair();
 * auto ct = sylvite::asymmetric::SealedBox::seal(data, kp.public_key);
 * auto pt = sylvite::asymmetric::SealedBox::open(ct, kp.private_key);
 * @endcode
 */
[[nodiscard]]
inline KeyPair crypto_generate_keypair() {
    sylvite::types::PublicKey pk_;
    sylvite::types::PrivateKey sk_ = sylvite::types::PrivateKey::crypto();

    crypto_box_keypair(pk_.data(), sk_.data());
    return { std::move(pk_), std::move(sk_) };
}

/**
 * @brief Generate an Ed25519 key pair for signing.
 *
 * @return KeyPair with a 32-byte public key and 64-byte private key.
 *
 * @par Security:
 *      The key pair is generated using libsodium's CSPRNG.
 *      The private key is 64 bytes: 32-byte scalar + 32-byte nonce prefix
 *      for deterministic nonce generation.
 *
 * @par Key sizes:
 *      - Public key: 32 bytes (crypto_sign_PUBLICKEYBYTES)
 *      - Private key: 64 bytes (crypto_sign_SECRETKEYBYTES)
 *
 * @par Example:
 * @code
 * auto kp = sylvite::asymmetric::sign_generate_keypair();
 * auto sig = sylvite::sign::sign(message, kp.private_key);
 * bool ok = sylvite::sign::verify(sig, message, kp.public_key);
 * @endcode
 */
[[nodiscard]]
inline KeyPair sign_generate_keypair() {
    sylvite::types::PublicKey pk_;
    sylvite::types::PrivateKey sk_ = sylvite::types::PrivateKey::sign();

    crypto_sign_ed25519_keypair(pk_.data(), sk_.data());
    return { std::move(pk_), std::move(sk_) };
}

} // namespace sylvite::asymmetric

#endif
