/**
 * @file kem.hpp
 * @brief Post-quantum Key Encapsulation Mechanisms (KEM): ML-KEM-768 and X-Wing.
 *
 * Provides post-quantum secure key encapsulation:
 *
 * **ML-KEM-768** (formerly CRYSTALS-Kyber):
 * - Lattice-based IND-CAA-secure KEM
 * - ~2^137 security against classical attacks, ~2^78 against quantum
 * - Key sizes: 1,184-byte public key, 2,400-byte secret key
 * - Encapsulates to 1,088-byte ciphertext, produces 32-byte shared secret
 *
 * **X-Wing**:
 * - Hybrid KEM combining ML-KEM-768 with Curve25519 Diffie-Hellman
 * - Provides both post-quantum and classical security in a single package
 * - Public key: 1,568 bytes, Ciphertext: 1,312 bytes
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use ML-KEM-768 keys beyond their operational lifetime** — Lattice-based
 *   algorithms like ML-KEM may need to be rotated as cryptanalysis advances.
 *   Monitor NIST standards and update keys periodically.
 * - **DON'T decapsulate with the wrong key and ignore the error** — If decapsulate()
 *   fails, the shared secret is invalid and any encryption done with it is broken.
 *   Don't silently continue with a bad shared secret.
 * - **DON'T use ML-KEM-768 shared secret directly as a long-term key** — The shared
 *   secret is meant for a session. For long-term keys, derive using HKDF or similar.
 * - **DON'T mix ML-KEM-768 and X-Wing ciphertexts** — They use different algorithms.
 *   A ciphertext from one cannot be opened by the other.
 *
 * @par When to use which:
 * - **ML-KEM-768**: Pure post-quantum security, smaller outputs
 * - **X-Wing**: Hybrid — combines post-quantum + classical DH for defense-in-depth
 *   (if ML-KEM-768 is broken, Curve25519 still protects)
 *
 * @par KEM vs. PKE:
 *      Unlike asymmetric encryption (Box/SealedBox) which encrypts a message
 *      directly, a KEM encapsulates a shared secret. You then use that
 *      shared secret with a symmetric cipher (like XChaCha20Poly1305).
 *
 * @par Example — ML-KEM-768:
 * @code
 * // Recipient generates a key pair
 * auto kp = sylvite::kem::MlKem768::generate_keypair();
 *
 * // Sender encapsulates a shared secret to the recipient's public key
 * auto [shared_secret, capsule] = sylvite::kem::MlKem768::encapsulate(kp.public_key);
 *
 * // Sender uses shared secret with symmetric crypto
 * auto ct = sylvite::symmetric::XChaCha20Poly1305::encrypt(message, shared_secret, nonce);
 *
 * // Recipient decapsulates the shared secret
 * auto ss = sylvite::kem::MlKem768::decapsulate(capsule, kp.secret_key);
 * auto pt = sylvite::symmetric::XChaCha20Poly1305::decrypt(ct, ss, nonce);
 * @endcode
 *
 * @par Example — X-Wing:
 * @code
 * auto kp = sylvite::kem::XWing::generate_keypair();
 * auto [ss, ct] = sylvite::kem::XWing::encapsulate(kp.public_key);
 * auto dec_ss = sylvite::kem::XWing::decapsulate(ct, kp.secret_key);
 * @endcode
 */

#ifndef SYLVITE_KEM_HPP
#define SYLVITE_KEM_HPP

#if (defined(_MSVC_LANG) ? _MSVC_LANG : __cplusplus) < 202002L
#error "C++20 or later is required to use Sylvite"
#endif

#include <cstdint>
#include <cstddef>
#include <vector>
#include <utility>
#include <stdexcept>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../types/publickey.hpp"
#include "../types/privatekey.hpp"
#include "../types/key.hpp"
#include "../types/ciphertext.hpp"

namespace sylvite::kem {

/**
 * @brief A public/private key pair for KEM operations.
 *
 * Holds both the public key (used for encapsulation) and the secret key
 * (used for decapsulation).
 *
 * @par Memory:
 *      Both keys use secure memory allocation (s_alloc) to prevent
 *      swapping. Private keys are wiped on destruction.
 */
struct KeyPair {
    sylvite::types::PublicKey public_key;   ///< The public key — can be shared freely.
    sylvite::types::PrivateKey secret_key; ///< The secret key — keep private and wipe after use.
};

namespace XWing {

/// @brief X-Wing public key size (1,568 bytes).
static constexpr std::size_t PUBLIC_KEY_SIZE = crypto_kem_PUBLICKEYBYTES;

/// @brief X-Wing secret key size (2,352 bytes).
static constexpr std::size_t SECRET_KEY_SIZE = crypto_kem_SECRETKEYBYTES;

/// @brief X-Wing shared secret size (32 bytes).
static constexpr std::size_t SHARED_KEY_SIZE = crypto_kem_SHAREDSECRETBYTES;

/// @brief X-Wing ciphertext size (1,312 bytes).
static constexpr std::size_t CIPHERTEXT_SIZE = crypto_kem_CIPHERTEXTBYTES;

/**
 * @brief Generate an X-Wing KEM key pair.
 *
 * X-Wing is a hybrid KEM that combines ML-KEM-768 with Curve25519
 * Diffie-Hellman for defense-in-depth: if either algorithm is broken,
 * the shared secret remains protected by the other.
 *
 * @return KeyPair with public_key (1,568 bytes) and secret_key (2,352 bytes).
 *
 * @throw SodiumRuntimeError if key generation fails (should not occur with valid inputs).
 *
 * @par Example:
 * @code
 * auto kp = sylvite::kem::XWing::generate_keypair();
 * auto [shared_secret, ciphertext] = sylvite::kem::XWing::encapsulate(kp.public_key);
 * @endcode
 */
[[nodiscard]]
inline KeyPair generate_keypair() {
    KeyPair kp;
    kp.public_key.resize(PUBLIC_KEY_SIZE);
    kp.secret_key.resize(SECRET_KEY_SIZE);

    if (crypto_kem_keypair(kp.public_key.data(), kp.secret_key.data()) != 0)
        throw sylvite::exceptions::SodiumRuntimeError("X-Wing KEM keypair generation failed.");

    return kp;
}

/**
 * @brief Encapsulate a shared secret to a public key (sender side).
 *
 * Generates a random shared secret and encapsulates it to the
 * recipient's public key. Anyone with the public key can do this;
 * only the recipient with the corresponding secret key can decapsulate.
 *
 * @param recipient_pk_ The recipient's X-Wing public key (1,568 bytes).
 *
 * @return std::pair<sylvite::types::Key, sylvite::types::CipherText>
 *         - first: the 32-byte shared secret (keep safe)
 *         - second: the 1,312-byte ciphertext (send to recipient)
 *
 * @throw SodiumLogicError if the public key size is invalid.
 * @throw SodiumRuntimeError if encapsulation fails.
 *
 * @par Shared secret:
 *      The returned shared secret is 32 bytes of cryptographically
 *      random data derived from the encapsulation process. Use it
 *      as a symmetric key for encryption with XChaCha20Poly1305.
 */
[[nodiscard]]
inline std::pair<sylvite::types::Key, sylvite::types::CipherText> encapsulate(
    sylvite::types::PublicKey& recipient_pk_
) {
    if (recipient_pk_.size() != PUBLIC_KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid X-Wing public key size. Expected " +
            std::to_string(PUBLIC_KEY_SIZE) + " bytes, got " +
            std::to_string(recipient_pk_.size())
        );
    }

    sylvite::types::CipherText ct_(CIPHERTEXT_SIZE);
    sylvite::types::Key ss_(SHARED_KEY_SIZE);

    if (crypto_kem_enc(
            ct_.data(),
            ss_.data(),
            recipient_pk_.data()) != 0)
        throw sylvite::exceptions::SodiumRuntimeError("X-Wing KEM encapsulation failed.");

    return { std::move(ss_), std::move(ct_) };
}

/**
 * @brief Decapsulate a shared secret from a ciphertext (recipient side).
 *
 * Uses the recipient's secret key to recover the shared secret from
 * the ciphertext produced by encapsulate().
 *
 * @tparam Alloc Optional allocator type for the shared secret (default: s_alloc).
 *
 * @param ciphertext_ The 1,312-byte ciphertext from encapsulate().
 * @param secret_key_ The recipient's 2,352-byte secret key.
 *
 * @return std::vector<std::uint8_t, Alloc> The 32-byte shared secret.
 *
 * @throw SodiumLogicError if:
 * - Ciphertext size is invalid
 * - Secret key size is invalid
 *
 * @throw SodiumLogicError if decapsulation fails (wrong key or tampered ciphertext).
 *
 * @par Security:
 *      Decapsulation will fail if the ciphertext was tampered with,
 *      ensuring that only intact ciphertexts produce the shared secret.
 */
template<typename Alloc = std::allocator<std::uint8_t>>
[[nodiscard]]
inline std::vector<std::uint8_t, Alloc> decapsulate(
    sylvite::types::CipherText& ciphertext_,
    sylvite::types::PrivateKey& secret_key_
) {
    if (ciphertext_.size() != CIPHERTEXT_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid X-Wing ciphertext size. Expected " +
            std::to_string(CIPHERTEXT_SIZE) + " bytes, got " +
            std::to_string(ciphertext_.size())
        );
    }
    if (secret_key_.size() != SECRET_KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid X-Wing secret key size. Expected " +
            std::to_string(SECRET_KEY_SIZE) + " bytes, got " +
            std::to_string(secret_key_.size())
        );
    }

    std::vector<std::uint8_t, Alloc> shared_secret(SHARED_KEY_SIZE);

    if (crypto_kem_dec(
            shared_secret.data(),
            ciphertext_.data(),
            secret_key_.data()) != 0)
    {
        throw sylvite::exceptions::SodiumLogicError(
            "X-Wing KEM decapsulation failed: invalid ciphertext or key.");
    }

    return shared_secret;
}

} // namespace XWing

namespace MlKem768 {

/// @brief ML-KEM-768 public key size (1,184 bytes).
static constexpr std::size_t PUBLIC_KEY_SIZE = crypto_kem_mlkem768_PUBLICKEYBYTES;

/// @brief ML-KEM-768 secret key size (2,400 bytes).
static constexpr std::size_t SECRET_KEY_SIZE = crypto_kem_mlkem768_SECRETKEYBYTES;

/// @brief ML-KEM-768 shared secret size (32 bytes).
static constexpr std::size_t SHARED_KEY_SIZE = crypto_kem_mlkem768_SHAREDSECRETBYTES;

/// @brief ML-KEM-768 ciphertext size (1,088 bytes).
static constexpr std::size_t CIPHERTEXT_SIZE = crypto_kem_mlkem768_CIPHERTEXTBYTES;

/**
 * @brief Generate an ML-KEM-768 KEM key pair.
 *
 * ML-KEM-768 is a post-quantum KEM based on the Module-LWE problem.
 * It provides ~2^137 security against classical attacks and ~2^78
 * against quantum attacks (as of 2024).
 *
 * @return KeyPair with public_key (1,184 bytes) and secret_key (2,400 bytes).
 *
 * @throw SodiumRuntimeError if key generation fails.
 *
 * @par Example:
 * @code
 * auto kp = sylvite::kem::MlKem768::generate_keypair();
 * @endcode
 */
[[nodiscard]]
inline KeyPair generate_keypair() {
    KeyPair kp;
    kp.public_key.resize(PUBLIC_KEY_SIZE);
    kp.secret_key.resize(SECRET_KEY_SIZE);

    if (crypto_kem_mlkem768_keypair(kp.public_key.data(), kp.secret_key.data()) != 0)
        throw sylvite::exceptions::SodiumRuntimeError("ML-KEM-768 keypair generation failed.");

    return kp;
}

/**
 * @brief Encapsulate a shared secret to an ML-KEM-768 public key.
 *
 * @param recipient_pk_ The recipient's ML-KEM-768 public key (1,184 bytes).
 *
 * @return std::pair<sylvite::types::Key, sylvite::types::CipherText>
 *         - first: the 32-byte shared secret
 *         - second: the 1,088-byte ciphertext
 *
 * @throw SodiumLogicError if the public key size is invalid.
 * @throw SodiumRuntimeError if encapsulation fails.
 */
[[nodiscard]]
inline std::pair<sylvite::types::Key, sylvite::types::CipherText> encapsulate(
    sylvite::types::PublicKey& recipient_pk_
) {
    if (recipient_pk_.size() != PUBLIC_KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid ML-KEM-768 public key size. Expected " +
            std::to_string(PUBLIC_KEY_SIZE) + " bytes, got " +
            std::to_string(recipient_pk_.size())
        );
    }

    sylvite::types::CipherText ct_(CIPHERTEXT_SIZE);
    sylvite::types::Key ss_(SHARED_KEY_SIZE);

    if (crypto_kem_mlkem768_enc(
            ct_.data(),
            ss_.data(),
            recipient_pk_.data()) != 0)
    {
        throw sylvite::exceptions::SodiumRuntimeError("ML-KEM-768 encapsulation failed.");
    }

    return { std::move(ss_), std::move(ct_) };
}

/**
 * @brief Decapsulate a shared secret from an ML-KEM-768 ciphertext.
 *
 * @tparam Alloc Optional allocator type (default: s_alloc for secure memory).
 *
 * @param ciphertext_ The 1,088-byte ciphertext from encapsulate().
 * @param secret_key_ The recipient's 2,400-byte secret key.
 *
 * @return sylvite::types::Key The 32-byte shared secret.
 *
 * @throw SodiumLogicError if ciphertext or secret key size is invalid.
 * @throw SodiumLogicError if decapsulation fails (wrong key or tampered ciphertext).
 *
 * @par Security:
 *      Uses s_alloc for secure memory allocation of the shared secret.
 *      The key is wiped when destroyed.
 *
 * @par Example:
 * @code
 * auto dec_ss = sylvite::kem::MlKem768::decapsulate(capsule, kp.secret_key);
 * auto pt = sylvite::symmetric::XChaCha20Poly1305::decrypt(ct, dec_ss, nonce);
 * @endcode
 */
template<typename Alloc = std::allocator<std::uint8_t>>
[[nodiscard]]
inline sylvite::types::Key decapsulate(
    sylvite::types::CipherText& ciphertext_,
    sylvite::types::PrivateKey& secret_key_
) {
    if (ciphertext_.size() != CIPHERTEXT_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid ML-KEM-768 ciphertext size. Expected " +
            std::to_string(CIPHERTEXT_SIZE) + " bytes, got " +
            std::to_string(ciphertext_.size())
        );
    }
    if (secret_key_.size() != SECRET_KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid ML-KEM-768 secret key size. Expected " +
            std::to_string(SECRET_KEY_SIZE) + " bytes, got " +
            std::to_string(secret_key_.size())
        );
    }

    sylvite::types::Key shared_secret(SHARED_KEY_SIZE);

    if (crypto_kem_mlkem768_dec(
            shared_secret.data(),
            ciphertext_.data(),
            secret_key_.data()) != 0)
    {
        throw sylvite::exceptions::SodiumLogicError(
            "ML-KEM-768 decapsulation failed: invalid ciphertext or key.");
    }

    return shared_secret;
}

} // namespace MlKem768

} // namespace sylvite::kem

#endif // SYLVITE_KEM_HPP
