/**
 * @file base.hpp
 * @brief Base class for all Sylvite buffer types.
 *
 * Provides the foundational `Base<T, Alloc>` class template that implements
 * the buffer management and secure memory operations used by all library types
 * (Key, Nonce, CipherText, String, etc.). It combines:
 * - std::vector semantics (iterator access, push_back, resize)
 * - Secure memory wiping (wipe())
 * - Sentinel handling for char buffers (null-terminated strings)
 * - Bounds-checked access (at()) and constant-time comparison (operator==)
 * - Secure allocation via s_alloc
 *
 * Base<T> is non-copyable for key types (see NonCopyable), preventing
 * accidental duplication of sensitive data.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T copy Key, Nonce, or other sensitive types** — use move semantics instead.
 *    Copying would duplicate sensitive material in memory, doubling attack surface.
 * - **DON'T use operator== to compare secrets in a way that leaks timing** — the
 *    overload IS constant-time, but comparing keys for equality is rarely needed and
 *    may indicate a design problem. For MAC/tag comparison, this is fine and intended.
 * - **DON'T access Key/Nonce data from multiple threads without synchronization** —
 *    Base<T> is not thread-safe.
 *
 * @par Memory layout:
 *      For char (String): [ data... | \0 ] — null sentinel at end
 *      For uint8_t (Key, Nonce, etc.): [ data... ] — no sentinel
 *
 * @par Thread safety:
 *      Base<T> itself is not thread-safe. External synchronization is
 *      required if multiple threads access the same instance. The wipe()
 *      operation uses sodium_memzero which is thread-safe.
 *
 * @par Example:
 * @code
 * Key key(32);                    // 32 bytes of secure memory
 * key.random_generate();          // fill with random data
 * auto sp = key.span_data();      // get a std::span for passing to crypto APIs
 * key.wipe();                     // zero out the key
 * @endcode
 */

#ifndef SYLVITE_BASE_CLASS_HPP
#define SYLVITE_BASE_CLASS_HPP

#include <concepts>
#include <utility>
#include <cstdint>
#include <memory>
#include <vector>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../internal/salloc.hpp"

namespace sylvite::internal {

/**
 * @brief Mixin to prevent copying of a class.
 *
 * Used for security-sensitive types (Key, Nonce, etc.) where copying would
 * duplicate sensitive material in memory. Move operations are still allowed.
 *
 * @par Why non-copyable?
 *      If a Key could be copied, sensitive key material would exist in
 *      two memory locations simultaneously, doubling the attack surface.
 *      Forcing moves instead of copies ensures key material stays in one place.
 *
 * @par Usage:
 *      Inherit publicly from NonCopyable to make your class non-copyable:
 *      @code
 *      class MyKey : public NonCopyable { ... };
 *      @endcode
 */
class NonCopyable {
protected:
    NonCopyable() = default;
    ~NonCopyable() = default;

public:
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;

    // Allow move operations
    NonCopyable(NonCopyable&&) = default;
    NonCopyable& operator=(NonCopyable&&) = default;
};

/**
 * @brief Base buffer class template for all Sylvite types.
 *
 * Provides common operations for managing a vector of T with optional
 * secure memory wiping and sentinel handling for char strings.
 *
 * @tparam T The element type (char for String, std::uint8_t for all others).
 * @tparam Alloc The allocator type. Defaults to std::allocator<T> for Base<char>,
 *               s_alloc<std::uint8_t> for byte buffers.
 *
 * @par Key methods:
 * - `at(idx)` — bounds-checked access, throws SodiumOutOfRangeError
 * - `operator[]` — unchecked access (faster, use when bounds are certain)
 * - `span_data()` — returns std::span for passing to crypto APIs
 * - `wipe()` — securely zeros memory (thread-safe)
 * - `operator==` — constant-time comparison (for comparing secrets)
 *
 * @par Sentinel behavior:
 *      When T is char (String type), the internal vector maintains a
 *      trailing '\0' sentinel. size() excludes this sentinel so the
 *      logical string length matches what you'd expect. When T is
 *      uint8_t (Key, Nonce, CipherText), no sentinel is used.
 *
 * @par Example:
 * @code
 * sylvite::types::Key key(32);
 * key.random_generate();
 * std::span<const std::uint8_t> key_span = key.span_data();
 * // pass to crypto functions that accept span
 * sylvite::symmetric::XChaCha20Poly1305::encrypt(plaintext, key, nonce);
 * @endcode
 */
template <typename T, typename Alloc = std::allocator<T>>
class Base {
protected:
    /// @brief True if T is char (enables null-sentinel handling).
    static constexpr bool is_char = std::same_as<T, char>;
    /// @brief Sentinel value: 1 for char (trailing \0), 0 for byte types.
    static constexpr std::size_t sentinel = is_char ? 1 : 0;

    /// @brief The underlying storage vector.
    std::vector<T, Alloc> vec_;

    /// @brief Default constructor — creates an empty buffer.
    Base() = default;

    /**
     * @brief Construct with a specific size.
     * @param n The number of elements (excluding sentinel for char).
     */
    explicit Base(std::size_t n) : vec_(n + sentinel) {
        if constexpr (is_char) {
            vec_.back() = '\0';
        }
    }

    /**
     * @brief Construct from a byte span.
     * @param view_ Span containing the initial data.
     *
     * Copies data from the span into the internal vector.
     */
    Base(std::span<const std::uint8_t> view_) : vec_(view_.begin(), view_.end()) {}

    /**
     * @brief Construct by moving a vector.
     * @param v_ The vector to take ownership of.
     */
    Base(std::vector<T, Alloc>&& v_) : vec_(std::move(v_)) {}

    /// @brief Throws SodiumEmptyStringError if the buffer is empty.
    void throw_empty_error() const {
        if constexpr (is_char) throw sylvite::exceptions::SodiumEmptyStringError(R"(Trying to use the "back" method on an empty String)");
        else throw sylvite::exceptions::SodiumEmptyStringError(R"(Trying to use the "back" method on an empty Buffer)");
    }

public:

    /**
     * @brief Bounds-checked element access.
     * @param idx Zero-based index.
     * @return T& Reference to the element at idx.
     * @throw sylvite::exceptions::SodiumOutOfRangeError if idx >= size().
     *
     * @par Time complexity: O(1)
     *
     * @par Example:
     * @code
     * try {
     *     auto& byte = key.at(0);
     * } catch (const SodiumOutOfRangeError&) { ... }
     * @endcode
     */
    T& at(std::size_t idx) {
        if (idx >= size()) throw sylvite::exceptions::SodiumOutOfRangeError("Index out of range");
        return vec_[idx];
    }

    /// @brief Const overload of at().
    const T& at(std::size_t idx) const {
        if (idx >= size()) throw sylvite::exceptions::SodiumOutOfRangeError("Index out of range");
        return vec_[idx];
    }

    /// @brief Returns true if the buffer contains no elements.
    /// @note For char types, an empty buffer is one with only the '\0' sentinel.
    [[nodiscard]] bool empty() const noexcept { return size() == 0; }

    /// @brief Returns the number of logical elements (excluding sentinel for char).
    /// @par For char: excludes the trailing '\0'. For uint8_t: same as vec_.size().
    [[nodiscard]] std::size_t size() const noexcept { return vec_.size() - sentinel; }

    /// @brief Returns the total capacity of the underlying vector (including sentinel).
    [[nodiscard]] std::size_t capacity() const noexcept { return vec_.capacity(); }

    /**
     * @brief Returns a const span over the data.
     * @return std::span<const T> A read-only view of the buffer.
     *
     * The span's size matches size(), not capacity().
     */
    [[nodiscard]] std::span<const T> span_data() const noexcept { return {vec_.data(), size()}; }

    /// @brief Returns a mutable span over the data.
    [[nodiscard]] std::span<T> span_data() noexcept { return {vec_.data(), size()}; }

    /// @brief Returns a const raw pointer to the data.
    [[nodiscard]] const T* data() const noexcept { return vec_.data(); }

    /// @brief Returns a mutable raw pointer to the data.
    [[nodiscard]] T* data() noexcept { return vec_.data(); }

    // --- Iterators ---

    /// @brief Returns a mutable iterator to the beginning.
    [[nodiscard]] auto begin() noexcept { return vec_.begin(); }
    /// @brief Returns a mutable iterator to the end (excludes sentinel for char).
    [[nodiscard]] auto end() noexcept { return vec_.end() - sentinel; }
    /// @brief Returns a mutable reverse iterator to the last element.
    [[nodiscard]] auto rbegin() noexcept { return vec_.rbegin() + sentinel; }
    /// @brief Returns a mutable reverse iterator to the beginning.
    [[nodiscard]] auto rend() noexcept { return vec_.rend(); }
    /// @brief Returns a const iterator to the beginning.
    [[nodiscard]] auto cbegin() const noexcept { return vec_.cbegin(); }
    /// @brief Returns a const iterator to the end (excludes sentinel for char).
    [[nodiscard]] auto cend() const noexcept { return vec_.cend() - sentinel; }
    /// @brief Returns a const reverse iterator to the last element.
    [[nodiscard]] auto crbegin() const noexcept { return vec_.crbegin() + sentinel; }
    /// @brief Returns a const reverse iterator to the beginning.
    [[nodiscard]] auto crend() const noexcept { return vec_.crend(); }

    /**
     * @brief Appends an element to the buffer.
     * @param b The element to append.
     *
     * For char (String): replaces the trailing '\0' with b, then appends new '\0'.
     * For uint8_t: simply appends b.
     *
     * @par amortized time: O(1) average
     */
    void push_back(T b) {
        if constexpr (is_char) {
            vec_.back() = b;
            vec_.push_back('\0');
        } else {
            vec_.push_back(b);
        }
    }

    /**
     * @brief Removes the last element.
     *
     * For char (String): sets the new last element to '\0'.
     * For uint8_t: removes the last element normally.
     *
     * @par time complexity: O(1)
     */
    void pop_back() noexcept {
        if constexpr (is_char) {
            if (vec_.size() > 1) {
                vec_.pop_back();
                vec_.back() = '\0';
            }
        } else {
            vec_.pop_back();
        }
    }

    /// @brief Requests the vector to shrink its capacity to fit its size.
    void shrink_to_fit() { vec_.shrink_to_fit(); }

    /**
     * @brief Securely wipes the buffer with zeros.
     *
     * Calls sodium_memzero on the underlying memory, overwriting all
     * bytes with zeros. After wiping:
     * - char (String): resizes to 1 and sets the single element to '\0'
     * - uint8_t: leaves the vector empty
     *
     * @par Thread safety:
     *     sodium_memzero is thread-safe. The wipe operation uses
     *     explicit_bzero semantics on platforms that support it,
     *     falling back to sodium_memzero on others.
     *
     * @par When to wipe:
     *     Typically called automatically when a Key goes out of scope
     *     (via destructor), but can be called explicitly after sensitive
     *     operations complete to reduce the window of exposure.
     *
     * @note For Key types, wipe() is called automatically in the destructor
     *       of the secure allocator's deallocate path, but calling it
     *       explicitly is still recommended after key usage to minimize
     *       the time key material remains in memory.
     *
     * @par Example:
     * @code
     * auto key = Argon2ID_derive_key(password, salt, 32);
     * // use key for one encryption
     * symmetric::XChaCha20Poly1305::encrypt(data, key, nonce);
     * key.wipe(); // explicit wipe immediately after use
     * @endcode
     */
    void wipe() noexcept {
        if (!vec_.empty()) {
            sodium_memzero(vec_.data(), vec_.size() * sizeof(T));
            if constexpr (is_char) {
                vec_.resize(1);
                vec_[0] = '\0';
            }
        }
    }

    /// @brief Returns a reference to the last element.
    /// @throw SodiumEmptyStringError if empty().
    T& back() {
        if (size() == 0) throw_empty_error();
        return vec_[vec_.size() - 1 - sentinel];
    }

    /// @brief Const overload of back().
    const T& back() const {
        if (size() == 0) throw_empty_error();
        return vec_[vec_.size() - 1 - sentinel];
    }

    /**
     * @brief Unchecked subscript access.
     * @param index Zero-based index.
     * @return T& Reference to the element.
     *
     * @warning No bounds checking. Use only when index is known to be valid.
     *          For safe access, use at().
     *
     * @par Time complexity: O(1)
     */
    T& operator[](std::size_t index) noexcept {
        return vec_[index];
    }

    /// @brief Const overload of operator[].
    const T& operator[](std::size_t index) const noexcept {
        return vec_[index];
    }

    /**
     * @brief Constant-time equality comparison.
     * @param other_ The buffer to compare against.
     * @return true if the buffers are identical byte-for-byte.
     *
     * Uses sodium_memcmp internally, which compares all bytes regardless
     * of content to avoid timing-based side channels. This is important
     * when comparing secrets (like MAC tags or hash outputs).
     *
     * @par Timing behavior:
     *     The comparison time is constant with respect to the number of
     *     differing bytes — it always compares the full buffer regardless
     *     of where the first difference occurs.
     *
     * @par Use cases:
     *     - Comparing MAC/authentication tags
     *     - Comparing hash outputs
     *     - Comparing keys (though Key equality is usually not needed)
     *
     * @par Example:
     * @code
     * auto expected_tag = HmacSha256::mac(data, key);
     * if (tag == expected_tag) { valid }
     * @endcode
     */
    bool operator==(const Base& other_) const noexcept {
        if (vec_.size() != other_.vec_.size()) return false;
        return sodium_memcmp(other_.vec_.data(), vec_.data(), vec_.size()) == 0;
    }

    /// @brief Inequality — returns !(operator==).
    bool operator!=(const Base& other_) const noexcept {
        return !(*this == other_);
    }

    /// @brief Returns true if the buffer is non-empty.
    /// @note For char (String), a buffer with only '\0' returns false.
    explicit operator bool() const noexcept { return !empty(); }
};

} // namespace sylvite::internal

#endif
