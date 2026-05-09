/**
 * @file concepts.hpp
 * @brief C++20 concepts used throughout Sylvite for type constraints.
 *
 * Defines reusable concepts that constrain template parameters in the
 * library's crypto APIs. These ensure type safety and API contract
 * compliance at compile time.
 *
 * Key concepts:
 * - `ContiguousByteContainer`: main constraint for crypto APIs accepting byte buffers
 * - `Container`: for types with standard iterator/size interface
 * - `byte_t`: for raw byte types (std::byte, std::uint8_t, unsigned char)
 *
 * @note These concepts defer to std/Boost-style concepts using requires clauses.
 */

#ifndef SYLVITE_CONCEPTS_HPP
#define SYLVITE_CONCEPTS_HPP

#include <concepts>
#include <cstdint>

namespace sylvite::concepts {

/**
 * @brief Concept satisfied if T matches any of the types in Ts... (variadic same_as).
 * @tparam T The type to check.
 * @tparam Ts The list of types to match against.
 *
 * Useful for constraining overloads to accept multiple specific types
 * while maintaining strict type checking.
 *
 * Example:
 * @code
 * template<sodium::concepts::same_as_any<T, std::uint8_t, char, unsigned char>
 * void process(T val);
 * @endcode
 */
template<typename T, typename... Ts>
concept same_as_any = (std::same_as<std::remove_cvref_t<T>, Ts> || ...);

/**
 * @brief Concept satisfied by raw byte types suitable for crypto operations.
 * @tparam T The type to check.
 *
 * Matches std::byte, std::uint8_t, and unsigned char. These are the
 * fundamental byte types used for crypto buffers throughout Sylvite.
 */
template<typename T>
concept byte_t = same_as_any<T, std::uint8_t, char, unsigned char>;

/**
 * @brief Concept satisfied by integral types (unsigned, signed, or bool).
 * @tparam T The type to check.
 *
 * Note: bool is explicitly excluded from Number in the Number concept below.
 */
template<typename T>
concept Integral =
    std::unsigned_integral<T> ||
    std::integral<T>;

/**
 * @brief Concept satisfied by arithmetic types (integers and floats).
 * @tparam T The type to check.
 *
 * Used primarily for random number generation where numeric bounds matter.
 * bool is excluded here (handled separately).
 */
template<typename T>
concept Number = std::is_arithmetic_v<T>;

/**
 * @brief Concept satisfied by types with standard container interface.
 * @tparam T The type to check.
 *
 * Requires: begin(), end(), cbegin(), cend(), crbegin(), crend(), size(),
 * data(), resize(std::size_t{}).
 *
 * This is less strict than ContiguousByteContainer and allows non-contiguous
 * or non-byte containers. Used for Sylvite APIs that work generically with containers.
 */
template<typename T>
concept Container = requires(T a) {
    a.begin();
    a.end();
    a.cbegin();
    a.cend();
    a.crbegin();
    a.crend();
    a.size();
    a.data();
    a.resize(std::size_t{});
};

/**
 * @brief Concept satisfied by types that are iterable (have begin/end/size).
 * @tparam T The type to check.
 *
 * A subset of Container without the data() and resize() requirements.
 * Useful for read-only iteration over data.
 */
template<typename T>
concept Iterable = requires(T a) {
    a.begin();
    a.end();
    a.cbegin();
    a.cend();
    a.size();
};

/**
 * @brief Concept satisfied by contiguous byte containers (main crypto API constraint).
 * @tparam T The type to check.
 *
 * Requires: a.data() returns a contiguous iterator, a.size() is convertible
 * to std::size_t, and sizeof(*a.data()) == 1 (i.e., it's a byte container).
 *
 * This is the primary constraint for symmetric/asymmetric encryption,
 * hashing, and other crypto primitives that need contiguous byte memory.
 *
 * @note std::string and std::vector<std::uint8_t> both satisfy this concept.
 *
 * Example:
 * @code
 * template<sylvite::concepts::ContiguousByteContainer T>
 * auto encrypt(const T& data, const Key& key);
 * @endcode
 */
template <typename T>
concept ContiguousByteContainer = requires(T a) {
    { a.data() } -> std::contiguous_iterator;
    { a.size() } -> std::convertible_to<std::size_t>;
    requires sizeof(*a.data()) == 1;
};

} // namespaces sodium::concepts

#endif
