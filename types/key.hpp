/**
 * @file key.hpp
 * @brief Symmetric key type for symmetric cryptography.
 *
 * Represents a symmetric key for use with symmetric crypto operations
 * (XChaCha20Poly1305, XSalsa20Box, etc.). Keys are:
 * - Non-copyable (prevents accidental duplication)
 * - Allocated with secure memory (s_alloc — locked, zeroed)
 * - Must be exactly 32 bytes for most symmetric algorithms
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T create keys from passwords directly** — passwords have low entropy.
 *    Use Argon2ID to derive a key from a password instead.
 * - **DON'T hardcode keys in source code** — they will end up in binaries and
 *    version control. Load keys from a secure configuration or key store.
 * - **DON'T serialize/log keys** — even encrypted keys in logs are a risk.
 * - **DON'T reuse the same key for many messages without a unique nonce per message** —
 *    Nonce reuse catastrophically breaks security. Generate a fresh nonce each time.
 * - **DON'T use keys of the wrong size** — always use 32 bytes for XChaCha20/XSalsa20.
 *    Using a key with the wrong size will throw SodiumLogicError at runtime.
 *
 * @par Key generation:
 *      Keys should be generated using random_generate():
 *      ```
 *      sylvite::types::Key key(32);
 *      key.random_generate();
 *      ```
 *
 * @par Key handling:
 *      Keys are sensitive data. Always:
 *      - Generate with random bytes (never reuse predictable keys)
 *      - Call wipe() or let the destructor clear them
 *      - Never log or serialize them unnecessarily
 *
 * @par Memory:
 *      Uses s_alloc<std::uint8_t> for secure storage. Memory is:
 *      - 16-byte aligned
 *      - Locked in RAM (no swap)
 *      - Zeroed before deallocation
 */

#ifndef SYLVITE_KEY_TYPE_HPP
#define SYLVITE_KEY_TYPE_HPP

#include <span>
#include <cstdint>
#include <utility>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/salloc.hpp"
#include "../internal/base.hpp"
#include "../init.hpp"

namespace sylvite::types {

/**
 * @brief A non-copyable symmetric key with secure memory storage.
 *
 * Inherits from Base<std::uint8_t, s_alloc<std::uint8_t>> to provide:
 * - Secure memory allocation via libsodium's sodium_malloc
 * - Secure wiping via sodium_memzero
 * - Non-copyable semantics via NonCopyable
 *
 * @par Construction:
 *      Keys are constructed with a specific size. For XChaCha20Poly1305
 *      and XSalsa20Box, the key must be 32 bytes:
 *      ```
 *      sylvite::types::Key key(32);
 *      key.random_generate();
 *      ```
 *
 * @par Destructor:
 *      The destructor calls wipe() via s_alloc's deallocate, ensuring
 *      secure erasure even on exception unwind.
 *
 * @par Move semantics:
 *      Move construction and move assignment ARE allowed, which is
 *      important for returning keys from functions efficiently.
 *
 * @par Example:
 *      ```
 *      sylvite::types::Key key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
 *      key.random_generate();
 *
 *      sylvite::types::Nonce nonce;
 *      auto ct = sylvite::symmetric::XChaCha20Poly1305::encrypt(
 *          plaintext, key, nonce
 *      );
 *      key.wipe(); // wipe after use
 *      ```
 */
class Key final : public sylvite::internal::Base<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>>, public sylvite::internal::NonCopyable {

    using B_ = Base<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>>;

public:
    /**
     * @brief Construct a key of the specified size.
     * @param size_ The size in bytes. Must match the algorithm's key size.
     *
     * @throw std::bad_alloc if memory allocation fails.
     *
     * @note Does not initialize the key — call random_generate() to fill
     *       with cryptographically random data.
     */
    explicit Key(std::size_t size_) : B_(size_) {
        sylvite::ensure_init();
    }

    /**
     * @brief Construct a key by taking ownership of a secure vector.
     * @param v_ A vector containing the key data.
     *
     * The vector must be allocated with s_alloc. After construction,
     * the Key takes exclusive ownership.
     */
    explicit Key(std::vector<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>>&& v_) {
        this->vec_ = std::move(v_);
    }

    /**
     * @brief Fill the key with cryptographically random bytes.
     *
     * Uses randombytes_buf() to fill the key with data from
     * libsodium's cryptographically secure RNG (CSPRNG).
     *
     * @par RNG source:
     *      - Windows: CryptGenRandom() via libsodium
     *      - Unix: /dev/urandom via libsodium
     *
     * @par Thread safety:
     *      randombytes_buf is thread-safe. Multiple threads can generate
     *      random bytes simultaneously.
     *
     * @par Example:
     *      ```
     *      sylvite::types::Key key(32);
     *      key.random_generate();
     *      ```
     */
    void random_generate() {
        randombytes_buf(this->data(), this->size());
    }
};

} // namespace sylvite::types

#endif
