/**
 * @file nonce.hpp
 * @brief Nonce (number used once) type for symmetric encryption.
 *
 * Represents a cryptographic nonce — a value that must only be used once
 * with a given key. Nonces are used to ensure that encrypting the same
 * plaintext twice produces different ciphertexts (semantic security).
 *
 * The Nonce class has two generation modes controlled by the Generation enum:
 * - `Generation::Lazy` (default): Nonce is generated lazily when first needed
 * - `Generation::Eager`: Nonce is generated immediately upon construction
 *
 * After use, a Nonce can be marked as "used" via NonceModify to prevent
 * accidental reuse. For increment-based AEAD modes, use increment() to
 * advance the counter.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T reuse a nonce with the same key** — This catastrophically breaks
 *    security. If the same nonce is used for two encryptions with the same key,
 *    an attacker can recover the XOR of the two plaintexts. ALWAYS generate a fresh
 *    nonce for each encryption, or use increment() for counter-based modes.
 * - **DON'T use nonces as message identifiers** — Nonces are not authenticated.
 *    If you need to identify which ciphertext a nonce came from, include a
 *    sequence number or unique ID in the AAD or plaintext.
 * - **DON'T use Lazy nonces for streaming or multi-step protocols** — Lazy nonces
 *    are generated internally inside encrypt(). You won't know the nonce value
 *    to store/transmit separately. Use Eager mode if you need to know the nonce.
 * - **DON'T use predictable nonces** — Nonces must be unpredictable to an attacker.
 *    Always use random_generate() to fill nonces with CSPRNG data.
 *
 * @par Why nonces matter:
 *      Reusing a nonce with the same key in most AEAD modes catastrophically
 *      breaks security — an attacker can recover the XOR of the two plaintexts.
 *      The library tries to help by tracking usage, but the programmer must
 *      still ensure nonces are unique per key.
 *
 * @par Default CTAD deduction guide:
 *      Nonce() → Nonce<Generation::Lazy>
 *      Nonce(n) → Nonce<Generation::Eager> where n is std::size_t
 *      Nonce(span) → Nonce<Generation::Eager>
 *
 * @par Example (Lazy mode — recommended for single use):
 *      ```
 *      sylvite::types::Nonce nonce; // Lazy — no allocation yet
 *      auto ct = XChaCha20Poly1305::encrypt(plaintext, key, nonce);
 *      // nonce automatically marked as used after encryption
 *      ```
 *
 * @par Example (Eager mode — for streaming/counters):
 *      ```
 *      sylvite::types::Nonce<Generation::Eager> nonce(24); // already random-filled
 *
 *      auto ct1 = XChaCha20Poly1305::encrypt(data1, key, nonce);
 *      nonce.increment(); // Advance counter for next block
 *      auto ct2 = XChaCha20Poly1305::encrypt(data2, key, nonce);
 *      ```
 */

#ifndef SYLVITE_NONCE_HPP
#define SYLVITE_NONCE_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"

namespace sylvite::types {

/**
 * @brief Controls when a Nonce generates its random content.
 *
 * @var Lazy  The nonce content is generated lazily — either when
 *            random_generate(n) is called, or when an encrypt function
 *            that uses Lazy nonces needs it. Default construction is
 *            essentially a no-op with no allocated memory.
 *
 * @var Eager The nonce allocates and fills its buffer immediately on
 *            construction (if given a size), or when random_generate()
 *            is called. Use this when you need to inspect or manipulate
 *            the nonce before use, or when using counter-based modes.
 *
 * @par Use Lazy when:
 *      - Doing single-shot encryption
 *      - You want minimal overhead
 *      - The nonce will be used exactly once
 *
 * @par Use Eager when:
 *      - Implementing a stream cipher with counter mode
 *      - You need to inspect or manually set nonce values
 *      - You're using nonces as part of a larger protocol
 */
enum class Generation {
    Lazy, // Generate the nonce only when a function will use it.
          // It is the default state for a constructor with no arguments.
    Eager // Generate the nonce the moment the object is created.
          // You must explicitly define a fixed size when creating the object.
};

/**
 * @brief A nonce (number used once) for AEAD symmetric encryption.
 *
 * A cryptographic nonce that must be unique per key for security.
 * Supports two generation modes via the Generation template parameter.
 *
 * @tparam M Generation mode (Lazy or Eager).
 *
 * @par Thread safety:
 *      Nonce objects are not thread-safe. Each encryption should use its
 *      own Nonce instance, or use proper synchronization.
 *
 * @par Size requirements:
 *      - XChaCha20Poly1305: 24 bytes (crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
 *      - XSalsa20Box: 24 bytes (crypto_secretbox_NONCEBYTES)
 *      - Curve25519 Box: 24 bytes (crypto_box_NONCEBYTES)
 *
 * @par Nonce reuse prevention:
 *      After XChaCha20Poly1305::encrypt uses a Lazy nonce, it marks it
 *      as used to prevent accidental reuse. Call random_generate() or
 *      increment() to reset the used flag before reusing the Nonce object.
 */
template<Generation M>
class Nonce final : public sylvite::internal::Base<std::uint8_t>, public sylvite::internal::NonCopyable {
    using B_ = sylvite::internal::Base<std::uint8_t>;
    volatile bool used_{false};
    friend class sylvite::internal::NonceModify;

    public:
    /// @brief Default constructor — only valid for Lazy generation mode.
    ///        Creates an empty Nonce that defers allocation until needed.
    explicit Nonce() requires (M == Generation::Lazy) = default;

    /**
     * @brief Construct an eager Nonce with a specific size.
     * @param n_ The size in bytes. Must match the algorithm's nonce size (e.g., 24 for XChaCha20).
     *
     * Allocates n_ bytes and immediately fills them with cryptographically random data
     * via randombytes_buf(). The nonce is ready to use upon construction.
     *
     * @throw std::bad_alloc if allocation fails.
     *
     * @par Example:
     *      ```
     *      // 24-byte nonce for XChaCha20Poly1305 — ready to use immediately
     *      sylvite::types::Nonce nonce(24);
     *      auto ct = XChaCha20Poly1305::encrypt(plaintext, key, nonce);
     *      ```
     */
    explicit Nonce(std::size_t n_) requires (M == Generation::Eager) : B_(n_) {}

    /**
     * @brief Construct an eager Nonce from an existing byte span.
     * @param view_ The span containing the nonce data to copy.
     *
     * Copies the data from view_ into the Nonce and marks it as "used"
     * since it was externally provided (not freshly generated).
     *
     * @tparam T Must be std::uint8_t, char, or unsigned char.
     */
    template<typename T>
    requires sylvite::concepts::same_as_any<T, std::uint8_t, char, unsigned char>
    explicit Nonce(std::span<const T> view_) requires (M == Generation::Eager) : B_(view_), used_(true) {}

    /**
     * @brief Initialize or reinitialize the nonce with a new size and random data (Lazy mode).
     * @param n_ The new size in bytes (e.g., 24 for XChaCha20Poly1305).
     *
     * Allocates or resizes the internal buffer to n_ bytes and fills it with
     * cryptographically random data. Also resets the used_ flag to false.
     *
     * @note Only available for Lazy mode nonces. For Eager mode, the size is fixed
     *       at construction — use random_generate() (no-arg) to re-randomize.
     *
     * @par Example:
     *      ```
     *      sylvite::types::Nonce nonce; // Lazy — not yet allocated
     *      nonce.random_generate(24);  // Allocate 24 bytes and fill with random data
     *      ```
     */
    void random_generate(std::size_t n_) {
        used_ = false;
        this->vec_.resize(n_);
        randombytes_buf(this->vec_.data(), this->vec_.size());
    }

    /**
     * @brief Randomize the nonce with fresh random data (Eager mode only).
     *
     * Fills the existing buffer with new cryptographically random bytes and
     * resets the used_ flag to false. The nonce size remains unchanged.
     *
     * @note Only available for Eager mode nonces. The nonce must already have
     *       a size > 0 (set at construction). If the buffer is empty, this is a no-op.
     *
     * @par When to use:
     *      After encrypting a message, call this to generate a fresh nonce
     *      for the next encryption without reallocating memory.
     *
     * @par Example:
     *      ```
     *      sylvite::types::Nonce<Generation::Eager> nonce(24); // random at construction
     *      auto ct1 = XChaCha20Poly1305::encrypt(data1, key, nonce);
     *      nonce.random_generate(); // fresh random nonce for next message
     *      auto ct2 = XChaCha20Poly1305::encrypt(data2, key, nonce);
     *      ```
     */
    void random_generate() noexcept requires (M == Generation::Eager) {
        used_ = false;
        if (this->vec_.size() > 0)
        randombytes_buf(this->vec_.data(), this->vec_.size());
    }

    /**
     * @brief Increment the nonce as a big-endian counter (Eager mode only).
     *
     * Treats the nonce bytes as a big-endian integer and increments it by one.
     * Use this for counter-mode encryption where each block uses a sequential
     * nonce value derived from a base random nonce.
     *
     * @note Only available for Eager mode nonces. Uses sodium_increment() which
     *       handles overflow by wrapping around (per libsodium's specification).
     *       The used_ flag is reset to false after incrementing.
     *
     * @par Important:
     *      First generate a random base nonce with random_generate(), then
     *      increment() for each subsequent block. Never start from zero.
     *
     * @par Example:
     *      ```
     *      sylvite::types::Nonce<Generation::Eager> nonce(24); // random at construction
     *      auto ct1 = XChaCha20Poly1305::encrypt(block1, key, nonce);
     *      nonce.increment(); // nonce = base + 1
     *      auto ct2 = XChaCha20Poly1305::encrypt(block2, key, nonce);
     *      nonce.increment(); // nonce = base + 2
     *      ```
     */
    void increment() noexcept requires (M == Generation::Eager) {
        if (!this->vec_.empty()) {
            used_ = false;
            sodium_increment(this->vec_.data(), this->vec_.size());
        }
    }

    /// @brief Returns true if this nonce has been used for encryption.
    ///
    /// The used_ flag is set by XChaCha20Poly1305::encrypt after successful
    /// encryption (for Lazy nonces), and reset by random_generate() or
    /// increment(). You can check this to detect accidental reuse.
    [[nodiscard]]
    bool used() const noexcept {
        return used_;
    }

    /// @brief Returns the Generation mode of this Nonce.
    [[nodiscard]] static constexpr Generation get_state() noexcept { return M; }
};

// CTAD deduction guides:
// Nonce()  → Nonce<Generation::Lazy>
Nonce() -> Nonce<Generation::Lazy>;
// Nonce(std::size_t) → Nonce<Generation::Eager>
Nonce(std::size_t) -> Nonce<Generation::Eager>;
// Nonce(std::span<const std::uint8_t>) → Nonce<Generation::Eager>
Nonce(std::span<const std::uint8_t>) -> Nonce<Generation::Eager>;
// Nonce(std::span<std::uint8_t>) → Nonce<Generation::Eager>
Nonce(std::span<std::uint8_t>) -> Nonce<Generation::Eager>;

} // namespace sylvite::types

#endif
