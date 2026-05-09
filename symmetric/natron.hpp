/**
 * @file natron.hpp
 * @brief Natron — high-level authenticated symmetric encryption, impossible to misuse.
 *
 * Natron is the equivalent of Python's Fernet but built on
 * XSalsa20-Poly1305 (crypto_secretbox). The name comes from the mineral
 * Na₂CO₃·10H₂O (hydrated sodium carbonate), used in ancient Egypt
 * to preserve and integrate — exactly what this module does with data:
 * it preserves and guarantees integrity.
 *
 * @par Token format (binary, before Base64 URL-safe encoding):
 * @code
 * ┌──────────┬───────────────────┬───────────────────────────────────────┐
 * │ version  │ timestamp         │ nonce + MAC + ciphertext              │
 * │ (1 byte) │ (8 bytes, uint64) │ (24 + 16 + len(plaintext) bytes)       │
 * └──────────┴───────────────────┴───────────────────────────────────────┘
 * @endcode
 *
 *  - **version** (1 byte):   Always `0x01` in this version. Allows
 *                             format evolution without breaking compatibility.
 *  - **timestamp** (8 bytes): Unix seconds (UTC) as big-endian uint64.
 *                             Enables TTL verification and detection of old tokens.
 *  - **nonce** (24 bytes):    Randomly generated on each encryption.
 *                             Embedded in the token — the user never touches it.
 *  - **MAC** (16 bytes):      Poly1305 — authenticates nonce + timestamp + version
 *                             as implicit AAD via the secretbox primitive.
 *  - **ciphertext**:          XSalsa20 stream XOR with the plaintext.
 *
 * @par Security properties:
 *  - Confidentiality:  XSalsa20 (256-bit key, 192-bit nonce)
 *  - Authentication:   Poly1305 MAC — detects any tampering
 *  - Freshness:        Timestamp + optional TTL — rejects old tokens
 *  - Unique nonce:     Generated with CSPRNG on each encryption
 *  - Versioning:       Version byte — allows future migration
 *  - Key rotation:     NatronMultiKey — tries multiple keys in order
 *
 * @par Basic usage:
 * @code
 *     sylvite::types::Key key(crypto_secretbox_KEYBYTES);
 *     key.random_generate();
 *
 *     // Encrypt
 *     std::string token = sylvite::symmetric::Natron::encrypt("hello world", key);
 *
 *     // Decrypt (no TTL)
 *     std::string plain = sylvite::symmetric::Natron::decrypt(token, key);
 *
 *     // Decrypt with 5-minute TTL
 *     std::string plain = sylvite::symmetric::Natron::decrypt(
 *         token, key, std::chrono::seconds(300)
 *     );
 * @endcode
 *
 * @par Key rotation:
 * @code
 *     sylvite::symmetric::NatronMultiKey mk({ new_key, old_key });
 *     std::string plain = mk.decrypt(token);  // tries new_key first
 *     std::string new_token = mk.rotate(token); // re-encrypts with new_key
 * @endcode
 *
 * @par Comparison with Fernet (Python):
 *  | Property          | Fernet            | Natron                     |
 *  |--------------------|-------------------|----------------------------|
 *  | Cipher            | AES-128-CBC       | XSalsa20                   |
 *  | Authentication     | HMAC-SHA256       | Poly1305                   |
 *  | Nonce/IV          | 128-bit random    | 192-bit random             |
 *  | Timestamp + TTL   | ✓                 | ✓                          |
 *  | Versioning        | ✓ (0x80)          | ✓ (0x01)                   |
 *  | Key rotation      | MultiFernet       | NatronMultiKey             |
 *  | Output encoding   | URL-safe Base64   | URL-safe Base64, no padding |
 */

#ifndef SYLVITE_NATRON_HPP
#define SYLVITE_NATRON_HPP

#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <initializer_list>

#include <sodium.h>
#include "../exceptions/exceptions.hpp"
#include "../types/key.hpp"
#include "../types/nonce.hpp"
#include "../internal/base.hpp"
#include "../utils/base64.hpp"

namespace sylvite::symmetric {

namespace natron_internal_ {

// ─────────────────────────────────────────────────────────────────
//  Natron format constants
// ─────────────────────────────────────────────────────────────────

/// Version byte embedded in every Natron token. Allows detecting
/// tokens from future versions and rejecting them with a clear error.
inline constexpr std::uint8_t NATRON_VERSION      = 0x01;

/// Size of the version field in bytes.
inline constexpr std::size_t  VERSION_SIZE        = 1;

/// Size of the timestamp field in bytes (big-endian uint64).
inline constexpr std::size_t  TIMESTAMP_SIZE      = 8;

/// Nonce size for XSalsa20 (crypto_secretbox).
inline constexpr std::size_t  NONCE_SIZE          = crypto_secretbox_NONCEBYTES;   // 24

/// Size of the Poly1305 MAC.
inline constexpr std::size_t  MAC_SIZE            = crypto_secretbox_MACBYTES;     // 16

/// Fixed header size (version + timestamp + nonce).
inline constexpr std::size_t  HEADER_SIZE         = VERSION_SIZE + TIMESTAMP_SIZE + NONCE_SIZE;

/// Total overhead per token relative to the plaintext.
inline constexpr std::size_t  OVERHEAD            = HEADER_SIZE + MAC_SIZE;

/// Minimum size of a valid token (header + MAC, no plaintext).
inline constexpr std::size_t  MIN_TOKEN_BYTES     = OVERHEAD;

/// Clock skew tolerance in seconds for timestamp validation.
inline constexpr std::uint64_t CLOCK_SKEW_TOLERANCE_SECS = 60;

// ─────────────────────────────────────────────────────────────────
//  Timestamp serialization (big-endian, portable)
// ─────────────────────────────────────────────────────────────────

/**
 * @brief Writes a uint64 in big-endian to the 8 bytes pointed by dst.
 * @param dst  Destination (must have at least 8 bytes available).
 * @param val  Value to serialize.
 */
inline void write_u64_be(std::uint8_t* dst, std::uint64_t val) noexcept {
    dst[0] = static_cast<std::uint8_t>((val >> 56) & 0xFF);
    dst[1] = static_cast<std::uint8_t>((val >> 48) & 0xFF);
    dst[2] = static_cast<std::uint8_t>((val >> 40) & 0xFF);
    dst[3] = static_cast<std::uint8_t>((val >> 32) & 0xFF);
    dst[4] = static_cast<std::uint8_t>((val >> 24) & 0xFF);
    dst[5] = static_cast<std::uint8_t>((val >> 16) & 0xFF);
    dst[6] = static_cast<std::uint8_t>((val >>  8) & 0xFF);
    dst[7] = static_cast<std::uint8_t>((val >>  0) & 0xFF);
}

/**
 * @brief Reads a big-endian uint64 from the 8 bytes pointed by src.
 * @param src  Source (must have at least 8 bytes).
 * @return     The deserialized uint64 value.
 */
inline std::uint64_t read_u64_be(const std::uint8_t* src) noexcept {
    return (static_cast<std::uint64_t>(src[0]) << 56)
         | (static_cast<std::uint64_t>(src[1]) << 48)
         | (static_cast<std::uint64_t>(src[2]) << 40)
         | (static_cast<std::uint64_t>(src[3]) << 32)
         | (static_cast<std::uint64_t>(src[4]) << 24)
         | (static_cast<std::uint64_t>(src[5]) << 16)
         | (static_cast<std::uint64_t>(src[6]) <<  8)
         | (static_cast<std::uint64_t>(src[7]) <<  0);
}
// ─────────────────────────────────────────────────────────────────
//  Core encryption / decryption (without TTL or version validation)
//  Used internally by Natron and NatronMultiKey.
// ─────────────────────────────────────────────────────────────────

/**
 * @brief Encrypts plaintext with the given key and returns the binary token.
 *
 * Builds the layout [ version | timestamp | nonce | MAC | ciphertext ]
 * and returns raw bytes (without Base64). The timestamp is the current
 * instant in Unix seconds.
 *
 * @param plaintext  Data to encrypt (any binary content or text).
 * @param key        Symmetric key of exactly crypto_secretbox_KEYBYTES bytes.
 * @return           Binary token ready to pass to b64_encode.
 */
inline std::vector<std::uint8_t> encrypt_raw(
    std::span<const std::uint8_t> plaintext,
    const sylvite::types::Key& key
) {
    if (key.size() != crypto_secretbox_KEYBYTES) {
        throw sylvite::exceptions::SodiumLogicError(
            "Natron internal: key size mismatch in encrypt_raw."
        );
    }
    // version (1) + timestamp (8) + nonce (24) + MAC (16) + ciphertext
    const std::size_t total = OVERHEAD + plaintext.size();
    std::vector<std::uint8_t> token(total);

    // ── version ──────────────────────────────────────────────────
    token[0] = NATRON_VERSION;

    // ── timestamp (big-endian uint64, Unix seconds) ──────────────
    const auto now = std::chrono::system_clock::now();
    const auto ts  = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()
        ).count()
    );
    write_u64_be(token.data() + VERSION_SIZE, ts);

    // ── random nonce ─────────────────────────────────────────────
    std::uint8_t* nonce_ptr = token.data() + VERSION_SIZE + TIMESTAMP_SIZE;
    randombytes_buf(nonce_ptr, NONCE_SIZE);

    // ── XSalsa20-Poly1305 encryption ─────────────────────────────
    // MAC and ciphertext go together starting at HEADER_SIZE
    std::uint8_t* mac_and_ct = token.data() + HEADER_SIZE;

    if (crypto_secretbox_easy(
            mac_and_ct,
            plaintext.data(), plaintext.size(),
            nonce_ptr,
            key.data()) != 0)
    {
        throw std::runtime_error("Natron: encryption failed.");
    }

    return token;
}

/**
 * @brief Decrypts a binary token with the given key.
 *
 * Validates version, extracts timestamp and nonce, verifies MAC, and decrypts.
 * Does not validate TTL — that's handled by the public layer.
 *
 * @param raw_token  Token bytes (already decoded from Base64).
 * @param key        Symmetric key.
 * @param[out] ts_out  If not nullptr, the token's timestamp is written here.
 * @return           Decrypted plaintext.
 *
 * @throws sylvite::exceptions::SodiumLogicError  If the token is malformed
 *         or the version is unknown.
 * @throws sylvite::exceptions::SodiumInvalidSignature  If the MAC is invalid
 *         (token corrupted, tampered, or wrong key).
 */
inline std::vector<std::uint8_t> decrypt_raw(
    std::span<const std::uint8_t> raw_token,
    const sylvite::types::Key& key,
    std::uint64_t* ts_out = nullptr
) {
    // ── minimum size validation ──────────────────────────────────
    if (raw_token.size() < MIN_TOKEN_BYTES) {
        throw sylvite::exceptions::SodiumLogicError(
            "Natron: token too short to be valid (" +
            std::to_string(raw_token.size()) + " bytes, minimum is " +
            std::to_string(MIN_TOKEN_BYTES) + ")."
        );
    }

    // ── version validation ───────────────────────────────────────
    if (raw_token[0] != NATRON_VERSION) {
        throw sylvite::exceptions::SodiumLogicError(
            "Natron: unknown token version 0x" +
            [&]() {
                char buf[3];
                std::snprintf(buf, sizeof(buf), "%02X", raw_token[0]);
                return std::string(buf);
            }() +
            ". This library only supports version 0x01."
        );
    }

    // ── timestamp extraction ─────────────────────────────────────
    const std::uint64_t ts = read_u64_be(raw_token.data() + VERSION_SIZE);
    if (ts_out) *ts_out = ts;

    // ── nonce extraction ─────────────────────────────────────────
    const std::uint8_t* nonce_ptr  = raw_token.data() + VERSION_SIZE + TIMESTAMP_SIZE;
    const std::uint8_t* mac_and_ct = raw_token.data() + HEADER_SIZE;
    const std::size_t   mac_ct_len = raw_token.size() - HEADER_SIZE;

    // ── decryption and MAC verification ──────────────────────────
    std::vector<std::uint8_t> plaintext(mac_ct_len - MAC_SIZE);

    if (crypto_secretbox_open_easy(
            plaintext.data(),
            mac_and_ct, mac_ct_len,
            nonce_ptr,
            key.data()) != 0)
    {
        // We don't distinguish between "invalid MAC" and "wrong key"
        // to avoid leaking information to attackers.
        throw sylvite::exceptions::SodiumInvalidSignature(
            "Natron: authentication failed — token is corrupted, "
            "tampered, or the key is incorrect."
        );
    }

    return plaintext;
}

} // namespace natron_internal_


// ─────────────────────────────────────────────────────────────────
//  Natron — public single-key API
// ─────────────────────────────────────────────────────────────────

/**
 * @brief Natron — authenticated symmetric encryption with TTL and versioning.
 *
 * All functions are static — Natron has no state of its own,
 * the key is passed explicitly on each call just like Fernet.
 *
 * @par Key properties:
 *  - Must be exactly `crypto_secretbox_KEYBYTES` (32 bytes) long.
 *  - Generate with `sylvite::random::generate_key(crypto_secretbox_KEYBYTES)`
 *    or with `key.random_generate()` on an already constructed Key(32).
 *  - **Never reuse** the same key with Natron and another distinct primitive.
 */
class Natron {
public:
    /// Required key size (32 bytes for XSalsa20-Poly1305).
    static constexpr std::size_t KEY_SIZE = crypto_secretbox_KEYBYTES;

    Natron() = delete; // Static methods only — do not instantiate.

    /**
     * @brief Encrypts plaintext and returns a URL-safe Base64 Natron token.
     *
     * Internally generates a random nonce. The resulting token includes
     * version, current Unix timestamp, nonce, MAC, and ciphertext — all
     * encoded in URL-safe Base64 without padding.
     *
     * @tparam T  Any contiguous byte container
     *            (std::string, std::vector<uint8_t>, etc.).
     * @param  plaintext  Data to encrypt.
     * @param  key        Key of exactly KEY_SIZE (32) bytes.
     * @return            Natron token as std::string URL-safe Base64.
     *
     * @throws sylvite::exceptions::SodiumLogicError  If the key has
     *         incorrect size.
     *
     * @par Example:
     * @code
     *     auto token = sylvite::symmetric::Natron::encrypt("secret", key);
     *     // → "AQ..." (URL-safe Base64, ~65 chars for 7 bytes of plaintext)
     * @endcode
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    [[nodiscard]]
    static std::string encrypt(
        const T& plaintext,
        const sylvite::types::Key& key
    ) {
        validate_key_(key);
        auto raw = natron_internal_::encrypt_raw(
            {reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size()},
            key
        );
        return sylvite::utils::Base64::encode(raw);
    }

    /// Overload for std::string (the most common case).
    [[nodiscard]]
    static std::string encrypt(
        const std::string& plaintext,
        const sylvite::types::Key& key
    ) {
        validate_key_(key);
        auto raw = natron_internal_::encrypt_raw(
            {reinterpret_cast<const std::uint8_t*>(plaintext.data()), plaintext.size()},
            key
        );
        return sylvite::utils::Base64::encode(raw);
    }

    /**
     * @brief Decrypts a Natron token and returns the plaintext.
     *
     * Verifies version, MAC, and optionally TTL. If any check fails,
     * throws an exception — never returns unauthenticated data.
     *
     * @param  token  Natron token (URL-safe Base64, with or without padding).
     * @param  key    Key of exactly KEY_SIZE (32) bytes.
     * @param  ttl    If specified, rejects tokens older than this
     *                number of seconds. No limit by default.
     * @return        Original plaintext as std::string.
     *
     * @throws sylvite::exceptions::SodiumLogicError       Token malformed,
     *         unknown version, wrong key size, or invalid Base64.
     * @throws sylvite::exceptions::SodiumInvalidSignature Invalid MAC
     *         (token tampered or wrong key).
     * @throws sylvite::exceptions::SodiumExpiredTokenError Token older
     *         than the specified TTL.
     *
     * @par Example:
     * @code
     *     // Without TTL
     *     auto plain = sylvite::symmetric::Natron::decrypt(token, key);
     *
     *     // With 5-minute TTL
     *     auto plain = sylvite::symmetric::Natron::decrypt(
     *         token, key, std::chrono::seconds(300)
     *     );
     * @endcode
     */
    [[nodiscard]]
    static std::string decrypt(
        std::string_view token,
        const sylvite::types::Key& key,
        std::optional<std::chrono::seconds> ttl = std::nullopt
    ) {
        validate_key_(key);

        const auto raw = utils::Base64::decode(token);
        std::uint64_t ts = 0;
        auto plaintext = natron_internal_::decrypt_raw(raw, key, &ts);

        // ── TTL verification ─────────────────────────────────────
        if (ttl.has_value()) {
            const auto now = std::chrono::system_clock::now();
            const auto now_secs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    now.time_since_epoch()
                ).count()
            );
            if (ts > now_secs + sylvite::symmetric::natron_internal_::CLOCK_SKEW_TOLERANCE_SECS) {
                throw sylvite::exceptions::SodiumLogicError(
                    "Natron: token timestamp is in the future by more than " +
                    std::to_string(sylvite::symmetric::natron_internal_::CLOCK_SKEW_TOLERANCE_SECS) +
                    "s — possible clock skew or token manipulation."
                );
            }
            const auto age_secs = (now_secs >= ts) ? (now_secs - ts) : 0;
            if (age_secs > static_cast<std::uint64_t>(ttl->count())) {
                throw sylvite::exceptions::SodiumExpiredTokenError(
                    "Natron: token has expired. Age: " +
                    std::to_string(age_secs) + "s, TTL: " +
                    std::to_string(ttl->count()) + "s."
                );
            }
        }

        return std::string(
            reinterpret_cast<const char*>(plaintext.data()),
            plaintext.size()
        );
    }

    /**
     * @brief Extracts the Unix timestamp from a token without decrypting it.
     *
     * Useful for inspecting a token's age before attempting decryption,
     * or for logging/auditing.
     *
     * @note  Does not verify the MAC — do not use for security decisions.
     *        For secure verification, use decrypt() with TTL.
     *
     * @param  token  URL-safe Base64 Natron token.
     * @return        Timestamp as std::chrono::system_clock::time_point.
     *
     * @throws sylvite::exceptions::SodiumLogicError  Malformed token.
     *
     * @par Example:
     * @code
     *     auto tp  = sylvite::symmetric::Natron::token_timestamp(token);
     *     auto age = std::chrono::system_clock::now() - tp;
     *     std::cout << "Token age: "
     *               << std::chrono::duration_cast<std::chrono::seconds>(age).count()
     *               << "s\n";
     * @endcode
     */
    [[nodiscard]]
    static std::chrono::system_clock::time_point token_timestamp(
        std::string_view token
    ) {
        const auto raw = sylvite::utils::Base64::decode(token);
        if (raw.size() < natron_internal_::MIN_TOKEN_BYTES) {
            throw sylvite::exceptions::SodiumLogicError(
                "Natron: token too short to extract timestamp."
            );
        }
        if (raw[0] != natron_internal_::NATRON_VERSION) {
            throw sylvite::exceptions::SodiumLogicError(
                "Natron: unknown token version — cannot extract timestamp."
            );
        }
        const std::uint64_t ts = natron_internal_::read_u64_be(
            raw.data() + natron_internal_::VERSION_SIZE
        );
        return std::chrono::system_clock::time_point(std::chrono::seconds(ts));
    }

private:
    /**
     * @brief Validates that the key has the correct size.
     * @throws sylvite::exceptions::SodiumLogicError If key.size() != KEY_SIZE.
     */
    static void validate_key_(const sylvite::types::Key& key) {
        if (key.size() != KEY_SIZE) {
            throw sylvite::exceptions::SodiumLogicError(
                "Natron: key must be exactly " +
                std::to_string(KEY_SIZE) +
                " bytes (crypto_secretbox_KEYBYTES), got " +
                std::to_string(key.size()) + "."
            );
        }
    }
};


// ─────────────────────────────────────────────────────────────────
//  NatronMultiKey — key rotation
// ─────────────────────────────────────────────────────────────────

/**
 * @brief NatronMultiKey — decryption with multiple keys for rotation.
 *
 * Equivalent to Python's MultiFernet. Maintains an ordered list of
 * keys: the first is the active key (used for encryption), the rest
 * are old keys still accepted for decryption.
 *
 * @par Typical rotation flow:
 * @code
 *     // Before rotation — only old key
 *     sylvite::symmetric::NatronMultiKey mk_old({ old_key });
 *
 *     // During rotation — new_key encrypts, old_key still decrypts
 *     sylvite::symmetric::NatronMultiKey mk({ new_key, old_key });
 *     std::string new_token = mk.rotate(old_token); // re-encrypts with new_key
 *
 *     // After rotation — old_key no longer needed
 *     sylvite::symmetric::NatronMultiKey mk_new({ new_key });
 * @endcode
 *
 * @par Key order:
 *  - The **first** key in the list is the active key for encryption.
 *  - Decryption tries keys **in order**: first match wins.
 *  - If no key decrypts the token, SodiumInvalidSignature is thrown.
 */
class NatronMultiKey {
public:
    /**
     * @brief Constructs a NatronMultiKey with a list of keys.
     *
     * @param keys  List of keys in preference order. The first
     *              is used for encryption. All must be KEY_SIZE bytes.
     *
     * @throws sylvite::exceptions::SodiumLogicError  If the list is empty
     *         or any key has the wrong size.
     *
     * @par Example:
     * @code
     *     sylvite::symmetric::NatronMultiKey mk({ new_key, old_key });
     * @endcode
     */
    explicit NatronMultiKey(std::initializer_list<std::reference_wrapper<const sylvite::types::Key>> keys)
        : keys_(keys)
    {
        if (keys_.empty()) {
            throw sylvite::exceptions::SodiumLogicError(
                "NatronMultiKey: at least one key is required."
            );
        }
        for (std::size_t i = 0; i < keys_.size(); ++i) {
            if (keys_[i].get().size() != Natron::KEY_SIZE) {
                throw sylvite::exceptions::SodiumLogicError(
                    "NatronMultiKey: key at index " + std::to_string(i) +
                    " has invalid size " + std::to_string(keys_[i].get().size()) +
                    " (expected " + std::to_string(Natron::KEY_SIZE) + ")."
                );
            }
        }
    }

    /**
     * @brief Encrypts using the active key (the first in the list).
     *
     * @param plaintext  Data to encrypt.
     * @return           URL-safe Base64 Natron token.
     *
     * @par Example:
     * @code
     *     auto token = mk.encrypt("sensitive data");
     * @endcode
     */
    [[nodiscard]]
    std::string encrypt(const std::string& plaintext) const {
        return Natron::encrypt(plaintext, keys_.front().get());
    }

    /**
     * @brief Decrypts trying keys in order until the correct one is found.
     *
     * Tries each key silently. Only throws if no key could decrypt
     * the token, or if the token is malformed/expired.
     *
     * @param  token  URL-safe Base64 Natron token.
     * @param  ttl    Optional TTL. If specified, applies to all keys.
     * @return        Decrypted plaintext.
     *
     * @throws sylvite::exceptions::SodiumInvalidSignature  No key could
     *         decrypt the token.
     * @throws sylvite::exceptions::SodiumExpiredTokenError Token expired
     *         (detected after successful decryption).
     * @throws sylvite::exceptions::SodiumLogicError        Token malformed.
     *
     * @par Example:
     * @code
     *     auto plain = mk.decrypt(token);
     *     auto plain = mk.decrypt(token, std::chrono::seconds(300));
     * @endcode
     */
    [[nodiscard]]
    std::string decrypt(
        std::string_view token,
        std::optional<std::chrono::seconds> ttl = std::nullopt
    ) const {
        // Decode Base64 once — don't repeat for each key
        const auto raw = sylvite::utils::Base64::decode(token);

        std::uint64_t ts = 0;
        for (const auto& key_ref : keys_) {
            try {
                auto plaintext = natron_internal_::decrypt_raw(raw, key_ref.get(), &ts);

                // Valid MAC — now verify TTL
                if (ttl.has_value()) {
                    const auto now_secs = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()
                        ).count()
                    );
                    const auto age = (now_secs >= ts) ? (now_secs - ts) : 0;
                    if (age > static_cast<std::uint64_t>(ttl->count())) {
                        throw sylvite::exceptions::SodiumExpiredTokenError(
                            "NatronMultiKey: token has expired. Age: " +
                            std::to_string(age) + "s, TTL: " +
                            std::to_string(ttl->count()) + "s."
                        );
                    }
                }

                return std::string(
                    reinterpret_cast<const char*>(plaintext.data()),
                    plaintext.size()
                );
            } catch (const sylvite::exceptions::SodiumInvalidSignature&) {
                // This key isn't the right one — try the next
                continue;
            }
            // SodiumExpiredTokenError and SodiumLogicError propagate upward
        }

        throw sylvite::exceptions::SodiumInvalidSignature(
            "NatronMultiKey: no key was able to decrypt the token. "
            "The token may be corrupted, tampered, or encrypted with "
            "a key not present in this NatronMultiKey instance."
        );
    }

    /**
     * @brief Re-encrypts a token with the active key (rotation).
     *
     * Decrypts with any available key and re-encrypts with the
     * first (the active one). Useful during key migration to
     * update old tokens without exposing the plaintext more than necessary.
     *
     * @param  token  Existing token (encrypted with any key).
     * @param  ttl    Optional TTL to validate before rotating.
     * @return        New token encrypted with the active key.
     *
     * @throws  The same exceptions as decrypt().
     *
     * @par Example:
     * @code
     *     // Rotate all old tokens to the new key
     *     for (auto& t : stored_tokens)
     *         t = mk.rotate(t);
     * @endcode
     */
    [[nodiscard]]
    std::string rotate(
        std::string_view token,
        std::optional<std::chrono::seconds> ttl = std::nullopt
    ) const {
        const std::string plaintext = decrypt(token, ttl);
        return encrypt(plaintext);
    }

    /// Number of keys in this instance.
    [[nodiscard]] std::size_t key_count() const noexcept { return keys_.size(); }

private:
    /// References to keys in preference order.
    /// Stored as reference_wrapper to avoid copying Keys
    /// (which use s_alloc and are NonCopyable).
    std::vector<std::reference_wrapper<const sylvite::types::Key>> keys_;
};

} // namespace sylvite::symmetric

#endif // SYLVITE_NATRON_HPP