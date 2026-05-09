/**
 * @file argon2id.hpp
 * @brief Argon2ID password-based key derivation.
 *
 * Provides Argon2ID key derivation — one of the most widely recommended
 * password-based KDFs. It is memory-hard, meaning it requires a large
 * amount of memory to compute, making GPU/ASIC attacks expensive.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use short or low-entropy passwords** — Argon2ID makes brute-force
 *   attacks slower, but a weak password (e.g., "password123") remains guessable.
 *   Enforce minimum password complexity requirements or use passphrases.
 * - **DON'T reuse a salt** — The same salt with the same password always produces
 *   the same key. Reusing salts allows attackers to precompute hashes. Always
 *   generate a fresh random salt for each derivation.
 * - **DON'T derive multiple keys from the same password+slot** — If you need
 *   multiple keys, either call Argon2ID multiple times with different salts, or
 *   use HKDF on the derived key to derive sub-keys.
 * - **DON'T use output key lengths less than 32 bytes** — Shorter keys have
 *   insufficient entropy for symmetric encryption. Always request at least 32 bytes.
 * - **DON'T use Argon2ID for non-password material** — If you already have a
 *   high-entropy key (e.g., from a CSPRNG or DH exchange), use HKDF instead.
 *   Argon2ID is designed for low-entropy passwords and is unnecessarily slow
 *   for high-entropy inputs.
 * - **DON'T catch and swallow exceptions silently** — If Argon2ID fails (e.g.,
 *   due to insufficient memory), don't pretend the operation succeeded.
 *   Fail visibly rather than continuing with a potentially broken key.
 *
 * @par What is Argon2ID:
 *      Argon2id is a password-based key derivation function that:
 *      1. Is memory-hard: requires significant RAM to compute
 *      2. Is CPU-hard: also requires significant CPU iterations
 *      3. Combines both data-dependent and data-independent memory access
 *         (the "id" variant) for resistance against GPU/ASIC and side-channel attacks
 *
 * @par Profiles:
 *      Three predefined parameter sets (opslimit/memlimit):
 *      - `Interactive`: ~0.1s, ~64 MiB — for frequently repeated operations
 *      - `Moderate`: ~0.2s, ~256 MiB — balanced for typical use
 *      - `Sensitive`: ~1.5s, ~1 GiB — maximum security, higher latency
 *
 * @par Usage:
 *      Always use a unique, random salt per derivation. Never reuse
 *      a salt for multiple keys — this would defeat the purpose of salting.
 *
 * @par Example:
 * @code
 * sylvite::types::Salt salt;
 * salt.random_generate();
 *
 * auto key = sylvite::kdf::Argon2ID_derive_key(
 *     password,
 *     salt,
 *     32,                    // output key length
 *     sylvite::kdf::Profile::Moderate
 * );
 * @endcode
 *
 * @par Security notes:
 *      - The minimum recommended output key length is 32 bytes.
 *      - The salt should be at least 16 bytes (the default size).
 *      - Argon2ID is resistant to GPU/ASIC attacks due to memory hardness,
 *        but passwords should still be high-entropy when possible.
 */

#ifndef SYLVITE_ARGON2ID_HPP
#define SYLVITE_ARGON2ID_HPP

#include <stdexcept>
#include "../frsdef.hpp"
#include <sodium.h>
#include "../types/string.hpp"
#include "../types/salt.hpp"
#include "../types/key.hpp"

namespace sylvite::kdf {

/**
 * @brief Argon2ID parameter profiles.
 *
 * These profiles provide sensible defaults for different security/performance
 * trade-offs. The opslimit and memlimit values are chosen by the libsodium
 * team based on current hardware capabilities.
 *
 * @var Interactive Suitable for operations repeated many times (e.g., per-message
 *                 encryption in an interactive session). Lowest latency.
 *                 Typical: ~64 MiB memory, ~0.1s on modern CPU.
 *
 * @var Moderate   Balanced profile for typical application use.
 *                 Typical: ~256 MiB memory, ~0.2s on modern CPU.
 *
 * @var Sensitive  Maximum security with highest latency.
 *                 Typical: ~1 GiB memory, ~1.5s on modern CPU.
 *
 * @par Choosing a profile:
 *      Use Interactive for frequently repeated operations (e.g., encrypting
 *      many messages in one session). Use Sensitive for infrequent operations
 *      where maximum security is required (e.g., encrypting data at rest).
 */
enum class Profile {
    Interactive, // Low latency, ~64 MiB memory
    Moderate,    // Balanced, ~256 MiB memory
    Sensitive    // Maximum security, ~1 GiB memory
};

namespace Argon2ID {

/**
 * @brief Derive a symmetric key from a password using Argon2ID.
 *
 * @param password_ The password to derive the key from.
 * @param salt_ A random salt (at least 16 bytes for Argon2ID).
 * @param out_len The desired output key length in bytes (minimum 32 recommended).
 * @param profile_ The parameter profile to use (default: Moderate).
 *
 * @return sylvite::types::Key The derived key of length out_len.
 *
 * @throw SodiumLogicError if:
 * - out_len is less than 32 bytes
 * - salt size doesn't equal crypto_pwhash_argon2id_SALTBYTES (16 bytes)
 *
 * @throw sylvite::exceptions::SodiumRuntimeError if the derivation fails (memory allocation failure, etc.).
 *
 * @par Salt requirement:
 *      The salt MUST be exactly crypto_pwhash_argon2id_SALTBYTES (16 bytes).
 *      Use sylvite::types::Salt() which defaults to this size.
 *
 * @par Example:
 * @code
 * sylvite::types::String password = // get from user //;
 * sylvite::types::Salt salt;
 * salt.random_generate();
 *
 * auto key = sylvite::kdf::Argon2ID::derive_key(
 *     password, salt, 32, sylvite::kdf::Profile::Moderate
 * );
 * @endcode
 *
 * @par Algorithm:
 *      Uses Argon2id variant 1.3 with:
 *      - Data-dependent memory access (first half of memory passes)
 *      - Data-independent memory access (second half of memory passes)
 *      This hybrid approach provides resistance against both:
 *      - GPU/ASIC attacks (memory hardness)
 *      - Side-channel attacks (data-independent first half)
 */
template <sylvite::concepts::ContiguousByteContainer T>
inline sylvite::types::Key derive_key(
    const T& password_,
    const sylvite::types::Salt& salt_,
    std::size_t out_len = 32,
    Profile profile_ = Profile::Moderate
) {
    if (out_len < 32) throw sylvite::exceptions::SodiumLogicError("The key must be at least 32 bytes long.");
    if (salt_.size() != crypto_pwhash_argon2id_SALTBYTES) {
        throw sylvite::exceptions::SodiumLogicError("Invalid salt size for Argon2id.\nExpected: " + std::to_string(crypto_pwhash_argon2id_SALTBYTES) + " bytes, but " + std::to_string(salt_.size()) + " was given.");
    }

    unsigned long long ops_, ram_;

    switch (profile_) {
        case Profile::Interactive:
            ops_ = crypto_pwhash_opslimit_interactive();
            ram_ = crypto_pwhash_memlimit_interactive();
            break;
        case Profile::Moderate:
            ops_ = crypto_pwhash_opslimit_moderate();
            ram_ = crypto_pwhash_memlimit_moderate();
            break;
        case Profile::Sensitive:
            ops_ = crypto_pwhash_opslimit_sensitive();
            ram_ = crypto_pwhash_memlimit_sensitive();
            break;
        default:
            throw std::invalid_argument("Unknown profile");
    }

    sylvite::types::Key derived_key(out_len);

    int res = crypto_pwhash(
        derived_key.data(),
        static_cast<unsigned long long>(derived_key.size()),
        password_.c_str(),
        password_.size(),
        salt_.data(),
        ops_,
        ram_,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (res != 0) {
        throw sylvite::exceptions::SodiumRuntimeError("Key derivation failed.");
    }

    return derived_key;
}

} // namespace Argon2ID

} // namespace sylvite::kdf

#endif
