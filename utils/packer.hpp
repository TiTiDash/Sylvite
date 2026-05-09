/**
 * @file packer.hpp
 * @brief Utilities for packing and unpacking binary data.
 *
 * Provides `Packer` class with static methods for:
 * - `pack()`: Concatenate multiple buffers into a single vector.
 * - `unpack()`: Split a buffer into parts with fixed or variable sizes.
 *
 * The pack format is simple concatenation: [data1][data2][...] with no headers
 * or metadata. The caller must know the layout when unpacking.
 *
 * @par pack() usage:
 *      ```
 *      auto combined = Packer::pack(salt, nonce, ciphertext);
 *      // combined = salt | nonce | ciphertext
 *      ```
 *
 * @par unpack() usage:
 *      ```
 *      auto [salt, nonce, ct] = Packer::unpack<16, 24, -1>(buffer);
 *      // salt: 16 bytes, nonce: 24 bytes, ct: remaining bytes
 *      ```
 *
 * @note The -1 sentinel value can only be used as the LAST template argument
 *       to indicate "take all remaining bytes".
 */

#ifndef SYLVITE_PACKER_HPP
#define SYLVITE_PACKER_HPP

#include <tuple>
#include <vector>
#include <numeric>
#include <span>
#include <cstddef>

#include "../frsdef.hpp"
#include "../concepts.hpp"

namespace sylvite::utils {

/**
 * @brief Utility class for packing multiple buffers into one,
 *        and unpacking a buffer into fixed-size or variable-size parts.
 *
 * @par Packing:
 *      pack() concatenates any number of containers (with size() and data())
 *      into a single std::vector<std::uint8_t>. The result has no headers
 *      or delimiters — just raw concatenation.
 *
 * @par Unpacking:
 *      unpack<Sizes...>() splits a buffer into parts according to the
 *      template arguments. Each Sizes value specifies:
 *      - A positive integer: take exactly that many bytes
 *      - -1 (sentinel): take all remaining bytes (only valid as the last argument)
 *
 * @par Thread safety:
 *      All methods are static and reentrant. No instance state is modified.
 *
 * @par Example — pack and unpack:
 *      ```
 *      sylvite::types::Salt salt;
 *      salt.random_generate();
 *      sylvite::types::Nonce nonce;
 *      nonce.random_generate();
 *      sylvite::types::CipherText ct = XChaCha20Box::encrypt(data, key);
 *
 *      // Pack into a single buffer for storage/transmission
 *      auto packed = sylvite::utils::Packer::pack(salt, nonce, ct);
 *      // Layout: [salt (16 bytes)][nonce (24 bytes)][ciphertext (...)]
 *
 *      // Unpack using known sizes
 *      auto [unpacked_salt, unpacked_nonce, unpacked_ct]
 *          = sylvite::utils::Packer::unpack<16, 24, -1>(packed);
 *      ```
 */
class Packer {

    /// @brief Implementation helper for unpack — processes indices via parameter pack.
    template<std::ptrdiff_t... Sizes, std::size_t... Is>
    static auto unpack_impl(std::span<const std::uint8_t> buffer_, std::index_sequence<Is...>) {
        // Static array of sizes for offset calculation
        constexpr std::ptrdiff_t sizes_arr[] = { Sizes... };

        /// @brief Compute byte offset for the i-th field
        auto get_offset = [&](std::size_t target_idx) {
            std::size_t offset = 0;
            for(std::size_t i = 0; i < target_idx; ++i) {
                offset += sizes_arr[i];
            }
            return offset;
        };

        // Build tuple by expanding Indices and extracting each subspan
        return std::make_tuple(
            ([&](std::size_t i) {
                std::size_t start = get_offset(i);
                std::ptrdiff_t len = sizes_arr[i];

                if (len == -1) {
                    // -1 means: take all bytes from start to end
                    return buffer_.subspan(start);
                }
                // Fixed size: take exactly len bytes
                return buffer_.subspan(start, len);
            }(Is))...
        );
    }

public:
    /**
     * @brief Pack multiple containers into a single byte vector.
     *
     * Concatenates the contents of all arguments into one vector.
     * All arguments must have cbegin() and cend() methods.
     *
     * @tparam Args Container types with begin/end/size interface.
     * @param args The containers to concatenate.
     * @return std::vector<std::uint8_t> The packed data.
     *
     * @par Complexity: O(total_size)
     *
     * @par Example:
     *      ```
     *      auto data = Packer::pack(key, nonce, ciphertext);
     *      ```
     */
    template<sylvite::concepts::Iterable... Args>
    [[nodiscard]] static std::vector<std::uint8_t> pack(const Args&... args) {
        std::size_t total_size = (0 + ... + args.size());

        std::vector<std::uint8_t> result;
        result.reserve(total_size);

        // Fold expression: insert each container's data into result
        (result.insert(result.end(), args.cbegin(), args.cend()), ...);

        return result;
    }

    /**
     * @brief Unpack a buffer into parts of specified sizes.
     *
     * Splits a buffer according to the Sizes... template arguments.
     * Each template argument specifies:
     * - A positive integer: take exactly that many bytes
     * - -1: take all remaining bytes (only valid as the LAST argument)
     *
     * @tparam Sizes... The sizes for each field. Use -1 for the last field
     *                  to indicate "remaining bytes".
     * @param buffer The packed data to split.
     * @return A std::tuple of std::span<const std::uint8_t> objects.
     *
     * @throw SodiumLogicError if -1 is used anywhere except the last position.
     *
     * @par Example:
     *      ```
     *      // salt: 16 bytes, nonce: 24 bytes, ciphertext: rest
     *      auto [salt, nonce, ct] = Packer::unpack<16, 24, -1>(packed);
     *
     *      // All fixed sizes:
     *      auto [a, b, c] = Packer::unpack<4, 8, 16>(buffer);
     *      ```
     *
     * @par Static assertion:
     *      A static_assert enforces that -1 can only appear as the
     *      last template argument, preventing ambiguity in parsing.
     */
    template<std::ptrdiff_t... Sizes>
    [[nodiscard]] static auto unpack(std::span<const std::uint8_t> buffer) {
        // Ensure -1 only appears as the last argument
        static_assert([]() constexpr {
            constexpr std::size_t N = sizeof...(Sizes);

            if constexpr (N > 1) {
                constexpr std::ptrdiff_t arr[] = { Sizes... };

                for (std::size_t i = 0; i < N - 1; ++i) {
                    if (arr[i] == -1) {
                        return false; // -1 not in last position
                    }
                }
            }
            return true;
        }(), "The value -1 can only be used as the last template argument.");

        return unpack_impl<Sizes...>(buffer, std::make_index_sequence<sizeof...(Sizes)>{});
    }
};

} // namespace sylvite::utils

#endif
