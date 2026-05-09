/**
 * @file salloc.hpp
 * @brief Secure memory allocator for Sylvite types.
 *
 * Provides `s_alloc<T>`, a C++20 allocator wrapper around libsodium's
 * secure memory functions. Memory allocated with s_alloc is:
 * - Initialized to zero before use
 * - Locked in RAM (cannot be swapped to disk) on supported platforms
 * - Wiped with sodium_memzero before deallocation
 *
 * This allocator is used by Key, PrivateKey, PublicKey, and String types
 * to ensure sensitive data never hits disk and is securely erased.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T allocate large buffers with s_alloc** — Locked memory counts against
 *    RLIMIT_MEMLOCK (Unix) or working set limits (Windows). Allocating too much
 *    can cause allocation failures or system instability.
 * - **DON'T rely solely on s_alloc for key protection** — While s_alloc prevents
 *    swapping and wipes on free, keys should still be explicitly wiped after use
 *    to minimize the window of exposure.
 * - **DON'T use s_alloc for non-sensitive data** — The secure allocation has
 *    overhead. Use std::allocator for regular data that doesn't need protection.
 * - **DON'T assume wiped memory is instantly unrecoverable** — While sodium_memzero
 *    uses explicit_bzero semantics, sophisticated attackers with memory access
 *    might still recover data. Defense in depth is important.
 *
 * @note On Windows, memory locking requires no special privileges but is
 *       limited by available physical RAM. On Unix, mlock(2) requires
 *       appropriate privileges (or sufficient RLIMIT_MEMLOCK).
 *
 * @par Platform behavior:
 * - Windows: VirtualLock() — pages are locked in working set
 * - Unix (POSIX): mlock(2) with MADV_DONTDUMP (if available)
 *
 * @par Usage with standard containers:
 * @code
 * std::vector<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>> secure_vec;
 * @endcode
 */

#ifndef SYLVITE_SECURE_ALLOCATOR_HPP
#define SYLVITE_SECURE_ALLOCATOR_HPP

#include <limits>
#include <exception>
#include <cstddef>
#include <new>

#include "../frsdef.hpp"
#include <sodium.h>

namespace sylvite::internal {

/**
 * @brief Secure allocator using libsodium's locked memory functions.
 *
 * A C++20 allocator that allocates memory using sodium_malloc(), which:
 * 1. Allocates zeroed memory (automatic zeroing by libsodium)
 * 2. Locks the memory to prevent swapping (sodium_malloc uses mlock/VirtualLock)
 * 3. Overwrites memory with zeros on deallocation via sodium_free()
 *
 * @tparam T The type to allocate. Only byte-aligned types (std::uint8_t,
 *           char, etc.) are meaningful for crypto use.
 *
 * @par Type requirements:
 *     s_alloc is designed for trivially copyable byte types. Using it
 *     with complex types may cause issues because sodium_malloc/sodium_free
 *     manage raw memory without calling T's constructors/destructors.
 *
 * @par Allocator traits:
 *     Uses std::allocator_traits for full C++20 allocator compatibility.
 *
 * @par Memory alignment:
 *     sodium_malloc guarantees 16-byte alignment, suitable for SIMD
 *     operations that crypto code sometimes uses internally.
 *
 * @par Example — secure vector:
 * @code
 * using SecureVec = std::vector<std::uint8_t, sylvite::internal::s_alloc<std::uint8_t>>;
 * SecureVec key(32);
 * randombytes_buf(key.data(), key.size());
 * // key is zeroed and freed securely when destroyed
 * @endcode
 */
template<typename T>
struct s_alloc {
    using value_type = T;          ///< The type this allocator produces.
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;

    /// @brief Default constructor (no state, no-throw).
    s_alloc() noexcept = default;

    /// @brief Converting constructor from s_alloc<U> — all s_alloc instances are equivalent.
    template<typename U>
    constexpr s_alloc(const s_alloc<U>&) noexcept {}

    /**
     * @brief Allocates uninitialized memory for n objects.
     *
     * Internally calls sodium_malloc(n * sizeof(T)). The memory is:
     * - Zeroed by libsodium before being returned
     * - Locked in RAM to prevent swapping
     * - 16-byte aligned
     *
     * @param n Number of objects of type T to allocate space for.
     * @return T* Pointer to allocated memory.
     *
     * @throw std::bad_alloc if allocation fails or n is too large.
     *
     * @par Security note:
     *     Unlike std::allocator::allocate, the returned memory is already
     *     zeroed. This prevents information leakage from previous allocations.
     *
     * @par Size limits:
     *     Throws std::bad_array_new_length if n * sizeof(T) exceeds
     *     std::numeric_limits<std::size_t>::max() / 2.
     */
    [[nodiscard]]
    T* allocate(std::size_t n) {
        if (sodium_init() < 0) throw sylvite::exceptions::SodiumRuntimeError("sodium_init failed.");
        if (n == 0) return nullptr;

        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
            throw std::bad_array_new_length();

        auto p = static_cast<T*>(sodium_malloc(n * sizeof(T)));
        if (!p) throw std::bad_alloc();

        return p;
    }

    /**
     * @brief Deallocates memory previously allocated with allocate().
     *
     * Calls sodium_free(p), which:
     * - Overwrites the memory region with zeros (sodium_memzero)
     * - Unlocks the memory from RAM
     * - Frees the memory back to the OS
     *
     * @param p Pointer returned by a prior call to allocate().
     * @param n Number of objects (must match the original allocate call).
     *
     * @par Security note:
     *     The overwrite-with-zeros happens BEFORE the memory is unlocked,
     *     ensuring sensitive data never hits disk.
     *
     * @note Both parameters must match the original allocate() call exactly.
     */
    void deallocate(T* p, std::size_t) noexcept {
        sodium_free(p);
    }

    /// @brief All s_alloc<T> and s_alloc<U> are considered equal.
    template<typename U>
    bool operator==(const s_alloc<U>&) const noexcept { return true; }

    /// @brief Inequality comparison (always false — all allocators are equal).
    template<typename U>
    bool operator!=(const s_alloc<U>&) const noexcept { return false; }
};

} // namespace sylvite::internal

#endif
