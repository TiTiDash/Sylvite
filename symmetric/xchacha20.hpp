/**
 * @file xchacha20.hpp
 * @brief Raw XChaCha20-Poly1305 AEAD symmetric encryption.
 *
 * Provides low-level XChaCha20-Poly1305-IETF authenticated encryption
 * with associated data (AEAD). Unlike XChaCha20Box, this operates
 * directly on provided Nonce objects rather than prepending the nonce
 * to the ciphertext.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T reuse a nonce with the same key** — Nonce reuse catastrophically breaks
 *   security. The XOR of the two plaintexts is exposed. Each encryption must use a
 *   unique nonce. The library tracks Lazy nonce usage but cannot prevent logical reuse.
 * - **DON'T use this for storing multiple related messages with sequential nonces** —
 *   If you need to encrypt a stream of related messages, use a proper stream cipher
 *   or ensure each message has an independently generated nonce, not just incremented.
 * - **DON'T assume decryption failure indicates a wrong key** — It could also mean
 *   the ciphertext was tampered with. Both return the same error. Don't leak which
 *   one it was through error messages or timing.
 *
 * @par Security properties:
 * - IND-CPA secure (ciphertext reveals nothing about plaintext under chosen-plaintext attack)
 * - AEAD (Authenticated Encryption with Associated Data):
 *   - Confidentiality: plaintext is hidden
 *   - Authentication: recipient can verify ciphertext hasn't been tampered with
 *   - Integrity: associated data (AAD) is also authenticated but not encrypted
 *
 * @par Algorithm details:
 * - XChaCha20: 256-bit stream cipher based on ChaCha20 with extended nonce (192-bit)
 * - Poly1305: Carter-Wegman MAC for authentication
 * - IETF: Internet Engineering Task Force variant with specific nonce/IV handling
 *
 * @par Nonce reuse danger:
 *      NEVER use the same nonce with the same key to encrypt two different
 *      messages. This catastrophically breaks security — the XOR of the two
 *      plaintexts is exposed.
 *
 * @par Example:
 *      ```
 *      sylvite::types::Key key(32);
 *      key.random_generate();
 *
 *      sylvite::types::Nonce<Generation::Eager> nonce(24);
 *      nonce.random_generate();
 *
 *      auto ct = sylvite::symmetric::XChaCha20Poly1305::encrypt(
 *          plaintext, key, nonce
 *      );
 *
 *      auto pt = sylvite::symmetric::XChaCha20Poly1305::decrypt(
 *          ct, key, nonce
 *      );
 *      ```
 */

#ifndef SYLVITE_XCHACHA20_POLY1305_HPP
#define SYLVITE_XCHACHA20_POLY1305_HPP

#include <exception>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>

#include <sodium.h>
#include "../frsdef.hpp"
#include "../concepts.hpp"
#include "../internal/base.hpp"
#include "../internal/noncemodify.hpp"
#include "../types/key.hpp"
#include "../types/nonce.hpp"
#include "../types/ciphertext.hpp"

namespace sylvite::symmetric::XChaCha20Poly1305 {

/**
 * @brief Nonce size for XChaCha20-Poly1305-ietf (192 bits = 24 bytes).
 */
static constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

/**
 * @brief Authentication tag size (128 bits = 16 bytes).
 */
static constexpr std::size_t MAC_SIZE = crypto_aead_xchacha20poly1305_IETF_ABYTES;

/**
 * @brief Total overhead per encryption: nonce (24) + MAC (16) = 40 bytes.
 */
static constexpr std::size_t OVERHEAD = NONCE_SIZE + MAC_SIZE;

/**
 * @brief Encrypt a plaintext using XChaCha20-Poly1305-IETF AEAD.
 *
 * @tparam M The Nonce generation mode (Lazy or Eager).
 * @tparam T ContiguousByteContainer type for the plaintext.
 *
 * @param plaintext_ The data to encrypt.
 * @param key_ The 32-byte symmetric key.
 * @param nonce_ The 24-byte nonce. Must be unique per key.
 * @param aad_ Optional additional authenticated data (not encrypted, but authenticated).
 *
 * @return sylvite::types::CipherText The ciphertext (plaintext + 16-byte MAC).
 *
 * @throw sylvite::exceptions::SodiumLogicError if:
 * - The provided Nonce object has already been used for encryption.
 * - nonce size is not 24 bytes
 *
 * @throw sylvite::exceptions::SodiumLogicError if the underlying crypto operation fails.
 *
 * @par AAD (Associated Data):
 *      If aad_ is provided, it is authenticated but not encrypted. The
 *      recipient must have the same AAD to successfully decrypt. This
 *      is useful for binding ciphertext to additional context (e.g.,
 *      a message ID, version number) without encrypting it.
 *
 * @par Nonce reuse prevention:
 *      For Lazy nonces, this function marks the nonce as used after
 *      encryption, preventing accidental reuse. For Eager nonces,
 *      you must call random_generate() or increment() before reusing.
 *
 * @par Example with AAD:
 *      ```
 *      auto ct = XChaCha20Poly1305::encrypt(
 *          plaintext, key, nonce,
 *          std::as_bytes(std::span_cast<const std::uint8_t>(message_id))
 *      );
 *      ```
 */
template<sylvite::types::Generation M, sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline sylvite::types::CipherText encrypt(
    const T& plaintext_,
    const sylvite::types::Key& key_,
    sylvite::types::Nonce<M>& nonce_,
    std::span<const std::uint8_t> aad_ = {}
) {
    if (nonce_.used()) {
        throw sylvite::exceptions::SodiumLogicError(
            "Nonce reuse detected: this nonce has already been used for encryption. "
            "Call random_generate() or increment() before reusing."
        );
    }
    if constexpr (M == sylvite::types::Generation::Lazy) {
        if (!nonce_) {
            nonce_.random_generate(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        }
    }
    if (nonce_.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        throw sylvite::exceptions::SodiumLogicError("Invalid Nonce size. The nonce measures " + std::to_string(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) + " bytes, but " + std::to_string(nonce_.size()) + " were given");
    }

    sylvite::types::CipherText ct_(plaintext_.size() + crypto_aead_xchacha20poly1305_IETF_ABYTES);

    unsigned long long w_len_;
    int res_ = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct_.data(), &w_len_,
        reinterpret_cast<const unsigned char*>(plaintext_.data()), plaintext_.size(),
        aad_.data(), aad_.size(),
        nullptr,
        nonce_.data(),
        key_.data()
    );
    if (res_ != 0) {
        throw sylvite::exceptions::SodiumRuntimeError("Encryption failed.");
    }
    sylvite::internal::NonceModify m_;
    m_.modify(nonce_, true);
    return ct_;
}

/**
 * @brief Decrypt a ciphertext using XChaCha20-Poly1305-IETF AEAD.
 *
 * @tparam T The output container type (default: std::vector<std::uint8_t>).
 * @tparam M The Nonce generation mode.
 *
 * @param ciphertext_ The ciphertext to decrypt (must include 16-byte MAC).
 * @param key_ The 32-byte symmetric key (same key used for encryption).
 * @param nonce_ The 24-byte nonce (same nonce used for encryption).
 * @param aad_ Optional additional authenticated data (must match encryption).
 *
 * @return T The decrypted plaintext.
 *
 * @throw sylvite::exceptions::SodiumRuntimeError if:
 * - Ciphertext is too short (< 16 bytes MAC)
 * - Decryption/authentication fails (tampered ciphertext or wrong key/nonce)
 *
 * @par Authentication failure:
 *      If the ciphertext has been modified, decryption will throw.
 *      There is no way to distinguish between "wrong key", "wrong nonce",
 *      and "tampered ciphertext" — all result in the same error.
 *
 * @par Example:
 *      ```
 *      auto ct = XChaCha20Poly1305::encrypt(plaintext, key, nonce);
 *      auto pt = XChaCha20Poly1305::decrypt<std::vector<std::uint8_t>>(
 *          ct, key, nonce
 *      );
 *      ```
 */
template<sylvite::concepts::Container T = std::vector<std::uint8_t>, sylvite::types::Generation M>
[[nodiscard]]
inline T decrypt(
    const sylvite::types::CipherText& ciphertext_,
    const sylvite::types::Key& key_,
    const sylvite::types::Nonce<M>& nonce_,
    std::span<const std::uint8_t> aad_ = {}
) {
    if (ciphertext_.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw sylvite::exceptions::SodiumRuntimeError("Ciphertext too short.");
    }

    std::size_t pt_len = ciphertext_.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    T temp_vec(pt_len);

    unsigned long long actual_pt_len;

    int res = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(temp_vec.data()), &actual_pt_len,
        nullptr,
        ciphertext_.data(), ciphertext_.size(),
        aad_.data(), aad_.size(),
        nonce_.data(),
        key_.data()
    );

    if (res != 0) {
        throw sylvite::exceptions::SodiumRuntimeError("Decryption failed: Integrity/Authentication error.");
    }

    return T(std::move(temp_vec));
}

} // namespace sylvite::symmetric::XChaCha20Poly1305

#endif
