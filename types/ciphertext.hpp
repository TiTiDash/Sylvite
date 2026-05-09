/**
 * @file ciphertext.hpp
 * @brief CipherText type for symmetric encryption output.
 *
 * Represents the output of an encryption operation — a buffer containing
 * the nonce (if prepended) and the ciphertext with authentication tag.
 * CipherText objects are non-copyable (move-only) to prevent accidental
 * duplication of sensitive encrypted data.
 *
 * @par CipherText layout:
 *      For most symmetric operations (XChaCha20Box, XSalsa20Box), the
 *      CipherText format is: [ nonce (24 bytes) | ciphertext+MAC ]
 *      For raw XChaCha20Poly1305, the nonce is managed separately.
 *
 * @par Size considerations:
 *      The CipherText will be larger than the plaintext:
 *      - XChaCha20Box: plaintext_size + 24 (nonce) + 16 (MAC)
 *      - XSalsa20Box: plaintext_size + 24 (nonce) + 16 (MAC)
 *
 * @par Example:
 * @code
 * auto ct = sylvite::symmetric::XChaCha20Box::encrypt(plaintext, key);
 * // ct.size() = plaintext.size() + 40 (nonce + MAC)
 * @endcode
 *
 * @note CipherText does not store what algorithm was used. The caller
 *       must know this when decrypting.
 */

#ifndef SYLVITE_CIPHERTEXT_TYPE_HPP
#define SYLVITE_CIPHERTEXT_TYPE_HPP

#include <type_traits>
#include <stdexcept>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../internal/base.hpp"

namespace sylvite::types {

/**
 * @brief A buffer type for holding ciphertext output from symmetric encryption.
 *
 * Non-copyable (move-only) buffer for storing encrypted data. Inherits
 * from Base<std::uint8_t> for standard container semantics and uses
 * the secure Base class's wipe capability for cleanup.
 *
 * @par Construction:
 *      Can be default-constructed (empty), constructed with a specific
 *      size, or constructed from an existing span of bytes.
 *
 * @par Move semantics:
 *      CipherText is move-only because copying would duplicate potentially
 *      sensitive encrypted data in memory. Move operations transfer
 *      ownership efficiently.
 *
 * @par Memory:
 *      Uses default allocator (std::allocator<std::uint8_t>), NOT s_alloc.
 *      This is intentional — ciphertext is not secret once encrypted,
 *      only the key is. Storing ciphertext doesn't need secure memory.
 *
 * @par Example:
 * @code
 * sylvite::types::CipherText ct(plaintext.size() + 40);
 * // or let the encrypt function construct it:
 * auto ct = sylvite::symmetric::XChaCha20Box::encrypt(plaintext, key);
 * @endcode
 */
class CipherText final : public sylvite::internal::Base<std::uint8_t>, public sylvite::internal::NonCopyable {
    using B_ = sylvite::internal::Base<std::uint8_t>;

    public:
    /// @brief Default constructor — creates an empty CipherText.
    explicit CipherText() = default;

    /**
     * @brief Construct a CipherText with a pre-allocated buffer.
     * @param n_ The size in bytes to allocate.
     *
     * Allocates n_ bytes of uninitialized memory. Useful when the
     * encrypt function needs a pre-sized output buffer.
     *
     * @note The memory is uninitialized (not zeroed). The encrypt
     *       function will fill it with the ciphertext.
     */
    explicit CipherText(std::size_t n_) : B_(n_) {}

    /**
     * @brief Construct a CipherText from an existing byte span.
     * @param v_ The span containing the ciphertext data to copy.
     *
     * Copies the data from the span into the CipherText buffer.
     */
    explicit CipherText(std::span<const std::uint8_t> v_) : B_(v_) {}
};

} // namespace sylvite::types

#endif
