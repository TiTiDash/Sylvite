/**
 * @file xsalsa20box.hpp
 * @brief XSalsa20-Poly1305 Box — legacy symmetric encryption (pre-XChaCha20).
 *
 * Provides XSalsa20-Poly1305 authenticated encryption, a predecessor to
 * XChaCha20-Poly1305. It uses the same Salsa20 stream cipher but with
 * an extended 192-bit nonce (XSalsa20 = Salsa20 with extended nonce).
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use XSalsa20Box for new code** — Use XChaCha20Box instead.
 *   XSalsa20Box uses the Salsa20 cipher which has known theoretical weaknesses
 *   (related to 8-round Salsa20). While not practically exploitable, XChaCha20
 *   has better security margins and should be preferred for new applications.
 * - **DON'T pass a non-empty AAD** — XSalsa20Box does not support additional
 *   authenticated data. Passing a non-empty aad_ parameter will throw SodiumLogicError.
 *   If you need AAD, you must use XChaCha20Box instead.
 * - **DON'T reuse a nonce** — Same catastrophic security risk as all other
 *   symmetric AEAD modes. Always generate a fresh nonce per encryption.
 *
 * @par Why use XSalsa20Box vs XChaCha20Box:
 *      XSalsa20Box is provided for compatibility with existing encrypted
 *      data. For new applications, prefer XChaCha20Box which has better
 *      security margins and is not based on the Salsa20 cipher (which
 *      has known theoretical weaknesses, though none are practically
 *      exploatable).
 *
 * @par Layout:
 *      Output: [ nonce (24 bytes) | ciphertext + MAC (16 bytes) | ... ]
 *      Total overhead: 40 bytes
 *
 * @par Key size:
 *      Unlike XChaCha20Box which requires a 32-byte key, XSalsa20Box
 *      uses crypto_secretbox which has a 32-byte key (crypto_secretbox_KEYBYTES).
 *
 * @par AAD:
 *      XSalsa20Box does NOT natively support additional authenticated data.
 *      The aad_ parameter exists for API consistency with XChaCha20Box
 *      but is rejected with SodiumLogicError if non-empty.
 *
 * @par Example:
 * @code
 * sylvite::types::Key key(32);
 * key.random_generate();
 *
 * auto ct = sylvite::symmetric::XSalsa20Box::encrypt(plaintext, key);
 * auto pt = sylvite::symmetric::XSalsa20Box::decrypt(ct, key);
 * @endcode
 */

#ifndef SYLVITE_XSALSA20_BOX_HPP
#define SYLVITE_XSALSA20_BOX_HPP

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

namespace sylvite::symmetric::XSalsa20Box {

/**
 * @brief Nonce size for XSalsa20 (24 bytes).
 */
static constexpr std::size_t NONCE_SIZE = crypto_secretbox_NONCEBYTES;

/**
 * @brief Authentication tag size (16 bytes).
 */
static constexpr std::size_t MAC_SIZE = crypto_secretbox_MACBYTES;

/**
 * @brief Total overhead: nonce (24) + MAC (16) = 40 bytes.
 */
static constexpr std::size_t OVERHEAD = NONCE_SIZE + MAC_SIZE;

/**
 * @brief Key size for XSalsa20Box (32 bytes).
 */
static constexpr std::size_t KEY_SIZE = crypto_secretbox_KEYBYTES;

/**
 * @brief Encrypt a plaintext using XSalsa20-Poly1305.
 *
 * Generates a random 24-byte nonce, encrypts the plaintext with XSalsa20,
 * authenticates with Poly1305, and prepends the nonce to the ciphertext.
 *
 * @tparam T ContiguousByteContainer type for the plaintext.
 *
 * @param plaintext_ The data to encrypt.
 * @param key_ The 32-byte symmetric key.
 * @param aad_ Ignored — XSalsa20Box does not support AAD. Present for
 *             API compatibility with XChaCha20Box.
 *
 * @return sylvite::types::CipherText The ciphertext with embedded nonce.
 *
 * @throw SodiumLogicError if:
 * - Key size is not 32 bytes
 * - aad_ is non-empty (AAD not supported)
 *
 * @throw sylvite::exceptions::SodiumRuntimeError if encryption fails.
 *
 * @par Note on AAD:
 *      XSalsa20Box does not support additional authenticated data.
 *      Passing a non-empty aad_ will throw SodiumLogicError.
 *      If you need AAD, use XChaCha20Box instead.
 *
 * @par Example:
 * @code
 * auto ct = XSalsa20Box::encrypt(plaintext, key);
 * @endcode
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline sylvite::types::CipherText encrypt(
    const T& plaintext_,
    const sylvite::types::Key& key_,
    std::span<const std::uint8_t> aad_ = {} // not natively supported,
                                            // reserved for API consistency
) {
    if (key_.size() != KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid key size for XSalsa20Box. Expected " +
            std::to_string(KEY_SIZE) +
            " bytes, got " + std::to_string(key_.size())
        );
    }
    if (!aad_.empty()) {
        throw sylvite::exceptions::SodiumLogicError(
            "XSalsa20Box (crypto_secretbox) does not support AAD. "
            "Use XChaCha20Box if you need additional authenticated data."
        );
    }

    sylvite::types::Nonce<sylvite::types::Generation::Eager> nonce_(NONCE_SIZE);
    nonce_.random_generate();

    sylvite::types::CipherText out_(OVERHEAD + plaintext_.size());

    std::copy(nonce_.data(), nonce_.data() + NONCE_SIZE, out_.data());

    int res_ = crypto_secretbox_easy(
        out_.data() + NONCE_SIZE,
        reinterpret_cast<const unsigned char*>(plaintext_.data()), plaintext_.size(),
        nonce_.data(),
        key_.data()
    );
    if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("XSalsa20Box encryption failed.");

    sylvite::internal::NonceModify().modify(nonce_, true);
    return out_;
}

/**
 * @brief Decrypt a ciphertext with embedded nonce.
 *
 * Extracts the 24-byte nonce from the start of the ciphertext,
 * then decrypts using XSalsa20-Poly1305.
 *
 * @tparam T The output container type (default: std::vector<std::uint8_t>).
 *
 * @param ciphertext_ The ciphertext with embedded nonce: [ nonce (24) | ciphertext+MAC ].
 * @param key_ The 32-byte symmetric key (same key used for encryption).
 *
 * @return T The decrypted plaintext.
 *
 * @throw SodiumLogicError if:
 * - Ciphertext is too short (< 40 bytes total)
 * - Key size is invalid
 *
 * @throw SodiumLogicError if decryption/authentication fails.
 *
 * @par Authentication failure:
 *      If the ciphertext has been modified, decryption throws
 *      SodiumLogicError ("authentication error"). There is no way to
 *      distinguish tampering from a wrong key — both produce the same error.
 *
 * @par Example:
 * @code
 * auto ct = XSalsa20Box::encrypt(plaintext, key);
 * auto pt = XSalsa20Box::decrypt<std::vector<std::uint8_t>>(ct, key);
 * @endcode
 */
template<sylvite::concepts::Container T = std::vector<std::uint8_t>>
[[nodiscard]]
inline T decrypt(
    const sylvite::types::CipherText& ciphertext_,
    const sylvite::types::Key& key_
) {
    if (ciphertext_.size() < OVERHEAD) {
        throw sylvite::exceptions::SodiumLogicError(
            "CipherText too short for XSalsa20Box: must be at least " +
            std::to_string(OVERHEAD) + " bytes (nonce + MAC). "
            "Was this ciphertext produced by XSalsa20Box::encrypt?"
        );
    }
    if (key_.size() != KEY_SIZE) {
        throw sylvite::exceptions::SodiumLogicError(
            "Invalid key size for XSalsa20Box."
        );
    }

    const unsigned char* nonce_ptr_ = ciphertext_.data();
    const unsigned char* ct_ptr_    = ciphertext_.data() + NONCE_SIZE;
    std::size_t ct_len_             = ciphertext_.size() - NONCE_SIZE;

    T plaintext_(ct_len_ - MAC_SIZE);
    unsigned long long pt_len_;

    int res_ = crypto_secretbox_open_easy(
        reinterpret_cast<unsigned char*>(plaintext_.data()),
        ct_ptr_, ct_len_,
        nonce_ptr_,
        key_.data()
    );
    if (res_ != 0) {
        throw sylvite::exceptions::SodiumLogicError(
            "XSalsa20Box decryption failed: authentication error or corrupted ciphertext."
        );
    }
    return plaintext_;
}

} // namespace sylvite::symmetric::XSalsa20Box

#endif // SYLVITE_XSALSA20_BOX_HPP
