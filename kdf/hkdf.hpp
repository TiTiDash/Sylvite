/**
 * @file hkdf.hpp
 * @brief HKDF key derivation from a master key.
 *
 * Provides HKDF (HMAC-based Key Derivation Function) for deriving
 * one or more subkeys from a master key. Unlike Argon2ID, HKDF is
 * not memory-hard and is not suitable for password-based derivation —
 * it assumes the input key is already a cryptographically strong
 * random key.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use HKDF for password-based key derivation** — HKDF assumes the
 *    input key is already high-entropy. For passwords, use Argon2ID which
 *    is memory-hard and slows down brute-force attacks.
 * - **DON'T reuse key_id + context combinations** — Each subkey from the same
 *    master key must use a unique (key_id, context) pair. Reusing them produces
 *    identical derived keys, breaking key separation.
 * - **DON'T use predictable master keys** — The master key must come from a
 *    CSPRNG or high-entropy source. Deriving subkeys from a weak master key
 *    produces weak subkeys.
 * - **DON'T skip context strings** — Context strings bind derived keys to their
 *    purpose. Without them, keys derived for encryption might accidentally work
 *    for MAC, causing subtle security bugs.
 *
 * @par When to use HKDF vs Argon2ID:
 *      Use HKDF when you have a high-entropy master key (e.g., from
 *      a DH key exchange or a CSPRNG) and want to derive multiple
 *      subkeys from it.
 *      Use Argon2ID when deriving a key from a password (low entropy).
 *
 * @par HKDF consists of two steps:
 *      1. **Extract**: Extract a pseudorandom key material (PRK) from
 *         the input key and optional salt using HMAC-SHA-512.
 *      2. **Expand**: Expand the PRK into multiple output bytes using
 *         HMAC-SHA-512 in counter mode.
 *
 * @par Subkey IDs:
 *      Each subkey derived from the same master key should use a unique
 *      `key_id_` (0-255). This ensures each derived key is independent.
 *
 * @par Example:
 * @code
 * sylvite::types::Key master_key(32);
 * master_key.random_generate();
 *
 * // Derive a 32-byte subkey for encryption
 * auto enc_key = sylvite::kdf::derive_subkey(
 *     master_key, 32, 0,
 *     std::as_bytes(std::span("encryption", 10))
 * );
 *
 * // Derive a 32-byte subkey for MAC
 * auto mac_key = sylvite::kdf::derive_subkey(
 *     master_key, 32, 1,
 *     std::as_bytes(std::span("mac", 3))
 * );
 * @endcode
 */

#ifndef SYLVITE_HKDF_HPP
#define SYLVITE_HKDF_HPP

#include <span>

#include "../types/key.hpp"

namespace sylvite::kdf {

/**
 * @brief Derive a subkey from a master key using HKDF-SHA-512.
 *
 * Derives a cryptographic key of a specified size from a master key,
 * a key ID (0-255), and a context string. The context string binds
 * the derived key to a specific application context, ensuring that keys
 * derived for different purposes are independent.
 *
 * @param m_key_ The 32-byte master key (must be high-entropy, not a password).
 * @param size_ The desired output key size in bytes (16-64 bytes).
 * @param key_id_ An identifier for this key (0-255). Must be unique per master key per context.
 * @param context_ An 8-byte context string identifying the purpose of this key.
 *
 * @return sylvite::types::Key The derived subkey of the requested size.
 *
 * @throw SodiumLogicError if:
 * - Master key is not 32 bytes
 * - Requested output size is < 16 or > 64 bytes
 *
 * @throw SodiumDerivationError if the underlying HKDF operation fails.
 *
 * @par Context string:
 *      The context_ should be a fixed 8-byte string that uniquely identifies
 *      the purpose of the derived key. For example:
 *      - "encr    " for encryption keys
 *      - "mac     " for MAC keys
 *      - "sign    " for signing keys
 *
 *      Using the same context and key_id_ for different purposes
 *      would produce the same derived key — don't do that.
 *
 * @par Output size limits:
 *      HKDF-SHA-512 can derive keys from 16 to 64 bytes.
 *      For longer keys, use multiple derive_subkey calls with
 *      different key_ids.
 *
 * @par Example:
 * @code
 * auto subkey = sylvite::kdf::derive_subkey(
 *     master_key,          // 32-byte master key
 *     32,                 // 32-byte output
 *     0,                  // key ID 0
 *     std::as_bytes(std::span("encryption", 10))
 * );
 * @endcode
 */
inline sylvite::types::Key derive_subkey(
    sylvite::types::Key& m_key_,
    std::size_t size_,
    std::uint64_t key_id_,
    std::span<const char, 8> context_
) {
    if (m_key_.size() != 32) throw sylvite::exceptions::SodiumLogicError("The Key size must be 32 bytes.");
    if (size_ < 16 || size_ > 64) throw sylvite::exceptions::SodiumLogicError("The output key size must be greater than 16 bytes and less than 64 bytes.");
    sylvite::types::Key k_(size_);
    int result_ = crypto_kdf_derive_from_key(
        k_.data(), k_.size(),
        key_id_, context_.data(),
        m_key_.data()
    );

    if (result_ != 0) throw sylvite::exceptions::SodiumDerivationError("Key derivation failed.");
    return k_;
}

} // namespace sylvite::kdf

#endif
