/**
 * @file xchacha20box.hpp
 * @brief XChaCha20-Poly1305 Box — authenticated encryption with prepended nonce.
 *
 * Provides XChaCha20-Poly1305-IETF encryption that automatically prepends
 * the nonce to the ciphertext. This makes the ciphertext self-contained —
 * the recipient doesn't need to know the nonce separately.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T reuse a nonce** — Same catastrophic risk as XChaCha20Poly1305.
 *   Each encrypt() call generates a fresh nonce internally. Don't reuse
 *   the same CipherText buffer for multiple encryptions.
 * - **DON'T use the same key for unrelated encryption flows that need separate
 *   nonce tracking** — The nonce is embedded in ciphertext. If you're decrypting
 *   many messages with the same key, each message's nonce is in its own ciphertext.
 *   But if you're encrypting a protocol where the nonce should be derived from a
 *   counter, use XChaCha20Poly1305 directly instead.
 * - **DON'T decrypt with the wrong key expecting a meaningful error** — Both wrong
 *   key and tampered ciphertext produce the same "authentication error" message.
 *   Don't differentiate them in logs or user-facing errors.
 *
 * @par Difference from XChaCha20Poly1305:
 *      XChaCha20Poly1305::encrypt takes a Nonce as a separate parameter.
 *      XChaCha20Box::encrypt embeds the nonce in the ciphertext output.
 *      XChaCha20Box::decrypt extracts the nonce from the ciphertext.
 *      Use XChaCha20Box when you want a single buffer to store/transmit.
 *
 * @par Layout:
 *      Output: [ nonce (24 bytes) | ciphertext + MAC (16 bytes) | ... ]
 *      Total overhead: 40 bytes
 *
 * @par Security properties:
 * - IND-CPA secure
 * - AEAD: authentication tag prevents tampering
 * - Nonce is authenticated as part of ciphertext integrity
 *
 * @par Example:
 * @code
 * sylvite::types::Key key(32);
 * key.random_generate();
 *
 * // Encryption — nonce is embedded in output
 * auto ct = sylvite::symmetric::XChaCha20Box::encrypt(plaintext, key);
 *
 * // Decryption — nonce is extracted automatically
 * auto pt = sylvite::symmetric::XChaCha20Box::decrypt(ct, key);
 * @endcode
 */

#ifndef SYLVITE_XCHACHA20_BOX_HPP
#define SYLVITE_XCHACHA20_BOX_HPP

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"
#include "../internal/noncemodify.hpp"
#include "../types/key.hpp"
#include "../types/nonce.hpp"
#include "../types/ciphertext.hpp"

namespace sylvite::symmetric::XChaCha20Box {

/**
 * @brief Nonce size for XChaCha20-Poly1305-ietf (24 bytes).
 */
static constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

/**
 * @brief Authentication tag size (16 bytes).
 */
static constexpr std::size_t MAC_SIZE = crypto_aead_xchacha20poly1305_IETF_ABYTES;

/**
 * @brief Total overhead added to plaintext size: 40 bytes (nonce + MAC).
 */
static constexpr std::size_t OVERHEAD = NONCE_SIZE + MAC_SIZE;

/**
 * @brief Encrypt a plaintext with a random nonce embedded in output.
 *
 * Generates a random 24-byte nonce, encrypts the plaintext, and prepends
 * the nonce to the ciphertext. The output is: [ nonce (24) | ciphertext+MAC ].
 *
 * @tparam T ContiguousByteContainer type for the plaintext.
 *
 * @param plaintext_ The data to encrypt.
 * @param key_ The 32-byte symmetric key.
 * @param aad_ Optional additional authenticated data (authenticated but not encrypted).
 *
 * @return sylvite::types::CipherText The ciphertext with embedded nonce.
 *
 * @throw SodiumLogicError if key size is not 32 bytes.
 * @throw sylvite::exceptions::SodiumRuntimeError if encryption fails (should not occur with valid inputs).
 *
 * @par Thread safety:
 *      This function is thread-safe. Each call generates a fresh random nonce.
 *
 * @par Example:
 * @code
 * auto ct = XChaCha20Box::encrypt(
 *     std::as_bytes(std::span(plaintext)), key
 * );
 * // ct contains: [24-byte nonce][ciphertext][16-byte MAC]
 * @endcode
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline sylvite::types::CipherText encrypt(
    const T& plaintext_,
    const sylvite::types::Key& key_,
    std::span<const std::uint8_t> aad_ = {}
) {
    if (key_.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid key size for XChaCha20Box. Expected " +
            std::to_string(crypto_aead_xchacha20poly1305_ietf_KEYBYTES) +
            " bytes, got " + std::to_string(key_.size())
        );
    }

    sylvite::types::Nonce<sylvite::types::Generation::Eager> nonce_(NONCE_SIZE);
    nonce_.random_generate();

    // Output layout: [ nonce | ciphertext+MAC ]
    sylvite::types::CipherText out_(OVERHEAD + plaintext_.size());

    // Copy nonce into output
    std::copy(nonce_.data(), nonce_.data() + NONCE_SIZE, out_.data());

    unsigned long long ct_len_;
    int res_ = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out_.data() + NONCE_SIZE, &ct_len_,
        reinterpret_cast<const unsigned char*>(plaintext_.data()), plaintext_.size(),
        aad_.data(), aad_.size(),
        nullptr,
        nonce_.data(),
        key_.data()
    );
    if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("XChaCha20Box encryption failed.");

    sylvite::internal::NonceModify().modify(nonce_, true);
    return out_;
}

/**
 * @brief Decrypt a ciphertext with embedded nonce.
 *
 * Extracts the 24-byte nonce from the start of the ciphertext,
 * then decrypts the remaining bytes.
 *
 * @tparam T The output container type (default: std::vector<std::uint8_t>).
 *
 * @param ciphertext_ The ciphertext with embedded nonce: [ nonce (24) | ciphertext+MAC ].
 * @param key_ The 32-byte symmetric key (same key used for encryption).
 * @param aad_ Optional additional authenticated data (must match encryption).
 *
 * @return T The decrypted plaintext.
 *
 * @throw SodiumLogicError if:
 * - Ciphertext is too short (< 40 bytes total)
 * - Key size is invalid
 *
 * @throw SodiumLogicError if decryption/authentication fails.
 *
 * @par Authentication:
 *      If the ciphertext or embedded nonce has been modified,
 *      decryption will throw SodiumLogicError ("authentication error").
 *
 * @par Example:
 * @code
 * auto ct = XChaCha20Box::encrypt(plaintext, key);
 * auto pt = XChaCha20Box::decrypt<std::vector<std::uint8_t>>(ct, key);
 * @endcode
 */
template<sylvite::concepts::Container T = std::vector<std::uint8_t>>
[[nodiscard]]
inline T decrypt(
    const sylvite::types::CipherText& ciphertext_,
    const sylvite::types::Key& key_,
    std::span<const std::uint8_t> aad_ = {}
) {
    if (ciphertext_.size() < OVERHEAD) {
        throw sylvite::exceptions::SodiumLogicError(
            "CipherText too short for XChaCha20Box: must be at least " +
            std::to_string(OVERHEAD) + " bytes (nonce + MAC). "
            "Was this ciphertext produced by XChaCha20Box::encrypt?"
        );
    }
    if (key_.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid key size for XChaCha20Box. Expected " + std::to_string(crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
            + ", but got " + std::to_string(key_.size()) + "."
        );
    }

    const unsigned char* nonce_ptr_ = ciphertext_.data();
    const unsigned char* ct_ptr_ = ciphertext_.data() + NONCE_SIZE;
    std::size_t ct_len_ = ciphertext_.size() - NONCE_SIZE;

    T plaintext_(ct_len_ - MAC_SIZE);
    unsigned long long pt_len_;

    int res_ = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(plaintext_.data()), &pt_len_,
        nullptr,
        ct_ptr_, ct_len_,
        aad_.data(), aad_.size(),
        nonce_ptr_,
        key_.data()
    );
    if (res_ != 0) {
        throw sylvite::exceptions::SodiumLogicError(
            "XChaCha20Box decryption failed: authentication error or corrupted ciphertext."
        );
    }
    return plaintext_;
}

} // namespace sylvite::symmetric::XChaCha20Box

#endif // SYLVITE_XCHACHA20_BOX_HPP
