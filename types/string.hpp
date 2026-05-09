/**
 * @file string.hpp
 * @brief Secure String type for text handling in Sylvite.
 *
 * Provides a secure string type that:
 * - Uses locked memory (s_alloc<char>) to prevent swapping
 * - Maintains a null terminator sentinel (always '\0'-terminated)
 * - Can be securely wiped when destroyed or when wipe() is called
 *
 * Unlike std::string, sylvite::types::String is:
 * - Non-copyable (prevents accidental duplication of string data)
 * - Securely allocated (locked in RAM, zeroed on deallocation)
 * - Always null-terminated (usable with C-style string APIs)
 *
 * @par Memory security:
 *      Uses s_alloc<char> for storage. Memory is:
 *      - Allocated with sodium_malloc (16-byte aligned, zeroed)
 *      - Locked in RAM (no swap)
 *      - Wiped with sodium_memzero before deallocation
 *
 * @par Null sentinel:
 *      The string maintains a trailing '\0' that is excluded from
 *      size() but included in capacity(). This makes the string
 *      directly usable with C APIs that expect null-terminated strings.
 *
 * @par Example:
 * @code
 * sylvite::types::String str(64); // pre-allocate 64 chars
 * std::cin >> str;               // read input
 * auto key = kdf::Argon2ID_derive_key(str, salt, 32);
 * str.wipe(); // wipe after use
 * @endcode
 *
 * @par getline support:
 *      Use sylvite::types::getline() for secure line reading with
 *      the delimiter of your choice (default '\n').
 *
 * @note This type is designed for sensitive data (passwords, keys
 *       derived from text). For non-sensitive strings, use std::string.
 */

#ifndef SYLVITE_STRING_HPP
#define SYLVITE_STRING_HPP

#include <span>
#include <cstdint>
#include <concepts>
#include <utility>
#include <iostream>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../internal/base.hpp"
#include "../init.hpp"
#include "../utils/utils.hpp"

namespace sylvite::types {

/**
 * @brief A secure, non-copyable, null-terminated string type.
 *
 * Uses s_alloc<char> for secure memory storage with locked pages
 * and automatic zeroing. Maintains a null terminator sentinel.
 *
 * @par Construction:
 *      - String(n): pre-allocate space for n characters (plus '\0')
 *      - String(): default, minimal allocation
 *      - From rvalue vector (takes ownership)
 *
 * @par Null termination:
 *      Always null-terminated. size() returns characters excluding '\0'.
 *      c_str() returns a const char* suitable for C APIs.
 *
 * @par Thread safety:
 *      Not thread-safe. Each string should be accessed from one thread
 *      or protected by synchronization.
 *
 * @par Example:
 * @code
 * sylvite::types::String password;
 * sylvite::utils::console::read_from_console("Password: ", password);
 * auto key = sylvite::kdf::Argon2ID_derive_key(password, salt, 32);
 * password.wipe(); // Always wipe sensitive strings!
 * @endcode
 */
class String final : public sylvite::internal::Base<char, sylvite::internal::s_alloc<char>>, sylvite::internal::NonCopyable {
    using B_ = sylvite::internal::Base<char, sylvite::internal::s_alloc<char>>;

public:
    /**
     * @brief Construct with initial capacity reservation.
     * @param init_cap_ Minimum number of characters to reserve (plus '\0').
     *
     * Allocates space for init_cap_ + 1 characters (the extra is for '\0').
     * The string starts empty (just '\0').
     *
     * @par Example:
     * @code
     * sylvite::types::String str(256); // room for 256 chars + '\0'
     * @endcode
     */
    explicit String(std::size_t init_cap_ = 32) {
            sylvite::ensure_init();
            if (init_cap_ > 0) {
                vec_.reserve(init_cap_ + 1);
            }
            vec_.push_back('\0');
        }

    /**
     * @brief Construct from a secure vector (takes ownership).
     * @param r_v The vector to take ownership of.
     *
     * If the vector doesn't end with '\0', one is appended.
     */
    explicit String(sylvite::utils::Vector<char>&& r_v) : B_(std::move(r_v)) {
        if (r_v.empty() || r_v.back() != '\0') {
            vec_.push_back('\0');
        }
    }

    /**
     * @brief Returns a const pointer to the null-terminated string data.
     * @return const char* Pointer suitable for C string APIs.
     *
     * @par Safety:
     *      The pointer is valid as long as the String is not modified
     *      or destroyed. Do not store this pointer long-term.
     */
    [[nodiscard]] const char* c_str() const noexcept {
        return vec_.data();
    }

    /**
     * @brief Swaps the contents of two strings in O(1) time.
     * @param other_ The string to swap with.
     *
     * No data is copied — only the internal vectors are swapped.
     * The swap is noexcept.
     */
    void swap(String& other_) noexcept {
        vec_.swap(other_.vec_);
    }
};

/**
 * @brief Swaps two String objects.
 * @param a First string.
 * @param b Second string.
 */
inline void swap(String& a, String& b) noexcept {
    a.swap(b);
}

/**
 * @brief Read a line from a stream into a secure String.
 *
 * Reads characters from `is` until `delim` is encountered, storing
 * them in `str`. The delimiter is not stored. The string is wiped
 * before reading.
 *
 * @param is The input stream to read from.
 * @param str The String to store the read characters.
 * @param delim The delimiter character (default '\n').
 * @return std::istream& Reference to `is`.
 *
 * @par Behavior:
 *      - Wipes `str` before reading
 *      - Skips leading '\n' or '\r\n' if delim is '\n'
 *      - Appends characters until delim is found
 *      - Does NOT store the delimiter
 *
 * @par Security:
 *      The input is read directly into the secure String buffer.
 *      On destruction or wipe(), the memory is zeroed.
 *
 * @par Example:
 * @code
 * sylvite::types::String input;
 * sylvite::types::getline(std::cin, input);
 * @endcode
 */
inline std::istream& getline(std::istream& is, String& str, char delim = '\n') {
    str.wipe();

    if (is.peek() == '\n' || (is.rdbuf()->in_avail() > 0 && is.peek() == '\r')) {
        is.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    char c;
    while (is.get(c)) {
        if (c == delim) {
            break;
        }
        str.push_back(c);
    }

    return is;
}

} // namespace sylvite::types
#endif
