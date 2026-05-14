/**
 * @file utils.hpp
 * @brief Common type aliases for Sylvite.
 *
 * Provides commonly used type aliases that combine standard library
 * types with Sylvite's secure allocator (s_alloc).
 *
 * @par Available aliases:
 * - `Vector<T>`: std::vector<T, s_alloc<T>> — a vector with secure memory
 * - `ByteString`: std::basic_string<std::uint8_t> — raw byte string
 * - `SodiumAllocator<T>`: alias for s_alloc<T>
 */

#ifndef SYLVITE_UTILS_HPP
#define SYLVITE_UTILS_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <array>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../internal/salloc.hpp"

namespace sylvite::utils {

/**
 * @brief A std::vector using Sylvite's secure allocator.
 *
 * Useful for creating vectors of sensitive data (keys, nonces, etc.)
 * that benefit from locked memory and automatic wiping.
 *
 * @par Example:
 * @code
 * sylvite::utils::Vector<std::uint8_t> secure_vec(32);
 * randombytes_buf(secure_vec.data(), secure_vec.size());
 * @endcode
 *
 * @tparam T The element type (typically std::uint8_t or char).
 */
template<typename T>
using Vector = std::vector<T, sylvite::internal::s_alloc<T>>;

/**
 * @brief A std::string of bytes (uint8_t instead of char).
 *
 * An alternative to Vector<std::uint8_t> for byte storage using
 * string semantics rather than vector semantics.
 *
 * @par Note:
 * Unlike String (sylvite::types::String), ByteString is NOT
 * null-terminated and does NOT use secure memory. Use it only
 * for non-sensitive byte storage.
 */
using ByteString = std::basic_string<std::uint8_t>;

/**
 * @brief Alias for Sylvite's secure allocator.
 *
 * Convenient shorthand for use in template parameters:
 * @code
 * std::vector<std::uint8_t, sylvite::utils::SodiumAllocator<std::uint8_t>>
 * @endcode
 */
template<typename T>
using SodiumAllocator = sylvite::internal::s_alloc<T>;

template<typename T, typename U>
void memory_compare(std::span<const T> A_, std::span<const U> B_) {
    if (A_.size() != B_.size()) throw sylvite::exceptions::SodiumLogicError("Buffers sizes mismatch.");
    if (sodium_memcmp(A_.data(), B_.data(), A_.size()) != 0) throw sylvite::exceptions::SodiumRuntimeError("Buffers mismatch.");
}

template<sylvite::concepts::ContiguousByteContainer T>
void memory_zero(T& buffer_) {
    sodium_memzero(buffer_.data(), buffer_.size());
}

} // namespace sylvite::utils

#endif
