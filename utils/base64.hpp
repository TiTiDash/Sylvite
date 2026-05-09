/**
 * @file base64.hpp
 * @brief Base64 and Hex encoding/decoding utilities.
 *
 * Provides functions for encoding binary data to Base64 or Hex strings,
 * and decoding Base64 or Hex strings back to binary data.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use Base64/Hex encoding for security** — Encoding is NOT encryption.
 *    Base64 and Hex are reversible transformations that provide no confidentiality.
 *    Anyone can decode them without a key.
 * - **DON'T mismatch encode/decode variants** — Encoding with Original and decoding
 *    with UrlSafe (or vice versa) will throw SodiumDecodificationError. Always use
 *    the same variant for both operations.
 * - **DON'T trust decoded data without validation** — After decoding, validate the
 *    data format and size before using it. Malicious input could be crafted to
 *    exploit downstream parsing.
 *
 * @par Base64 variants:
 * - `Variant::Original` — Standard Base64 with padding ('=')
 * - `Variant::OriginalNoPadding` — Standard Base64 without padding
 * - `Variant::UrlSafe` — URL-safe Base64 with +/ instead of +/
 * - `Variant::UrlSafeNoPadding` — URL-safe without padding
 *
 * @par Example:
 * @code
 * auto b64 = sylvite::utils::Base64::encode(data);
 * auto data2 = sylvite::utils::Base64::decode(b64);
 *
 * // URL-safe variant for HTTP headers
 * auto urlb64 = sylvite::utils::Base64::encode(data, Variant::UrlSafe);
 * @endcode
 */

#ifndef SYLVITE_BASE64_HPP
#define SYLVITE_BASE64_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../types/string.hpp"

namespace sylvite::utils {

namespace Base64 {

/**
 * @brief Base64 encoding variants.
 *
 * @var Original        Standard Base64 (RFC 4648) with '=' padding.
 * @var OriginalNoPadding Standard Base64 without padding.
 * @var UrlSafe         URL-safe Base64 using - and _ instead of + and /.
 * @var UrlSafeNoPadding URL-safe Base64 without padding.
 *
 * @par When to use which:
 * - Use Original for general binary data encoding (e.g., email attachments).
 * - Use UrlSafe for encoding data in URL path segments or query parameters.
 */
enum class Variant {
    Original = sodium_base64_VARIANT_ORIGINAL,
    OriginalNoPadding = sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
    UrlSafe = sodium_base64_VARIANT_URLSAFE,
    UrlSafeNoPadding = sodium_base64_VARIANT_URLSAFE_NO_PADDING
};

/**
 * @brief Encode binary data to a Base64 string.
 *
 * @param data_ The binary data to encode.
 * @param variant_ The Base64 variant to use (default: Original).
 * @return std::string The Base64-encoded string (without null terminator).
 *
 * @par Output size:
 *      The output string's length is computed by libsodium as:
 *      `((input_size + 2) / 3) * 4` for standard, slightly less for no-padding variants.
 *
 * @par Example:
 * @code
 * auto b64 = sylvite::utils::Base64::encode(key.span_data());
 * std::cout << "Encoded: " << b64 << '\n';
 * @endcode
 */
[[nodiscard]]
inline std::string encode(std::span<const std::uint8_t> data_, Variant variant_ = Variant::Original) {
    std::size_t out_size_ = sodium_base64_ENCODED_LEN(data_.size(), static_cast<int>(variant_));
    std::string out_(out_size_, '\0');

    sodium_bin2base64(
        out_.data(), out_.size(),
        data_.data(), data_.size(),
        static_cast<int>(variant_)
    );

    // Remove trailing null that libsodium may have written
    if (!out_.empty() && out_.back() == '\0') {
        out_.pop_back();
    }
    return out_;
}

/**
 * @brief Decode a Base64 string to binary data.
 *
 * @tparam C_ The output container type (default: std::vector<std::uint8_t>).
 * @param view_ The Base64 string to decode.
 * @param variant_ The Base64 variant (must match how it was encoded).
 * @return C_ The decoded binary data.
 *
 * @throw SodiumDecodificationError if the input is not valid Base64,
 *        has wrong padding, or uses the wrong variant.
 *
 * @par Variant matching:
 *      The decode variant must match the encode variant. Decoding
 *      URL-safe Base64 with Original variant (or vice versa) will throw.
 *
 * @par Example:
 * @code
 * auto decoded = sylvite::utils::Base64::decode<std::vector<std::uint8_t>>(
 *     "SGVsbG8gV29ybGQ=", Variant::Original
 * );
 * @endcode
 */
template<sylvite::concepts::Container C_ = std::vector<std::uint8_t>>
[[nodiscard]]
inline C_ decode(std::string_view view_, Variant variant_ = Variant::Original) {
    // Maximum output size: each 4 Base64 chars → 3 bytes
    std::size_t max_bin_len_ = (view_.size() / 4) * 3 + 2;

    C_ b_(max_bin_len_);
    std::size_t fsz_;

    int result = sodium_base642bin(
        reinterpret_cast<unsigned char*>(b_.data()), b_.size(),
        view_.data(), view_.size(),
        nullptr, &fsz_, nullptr,
        static_cast<int>(variant_)
    );

    if (result != 0) {
        throw sylvite::exceptions::SodiumDecodificationError("Base64 decodification failed.");
    }

    b_.resize(fsz_);
    return b_;
}

/**
 * @brief Decode a Base64 string (overload taking sylvite::types::String).
 *
 * @tparam C_ The output container type (default: std::vector<std::uint8_t>).
 * @param view_ The sylvite::types::String to decode.
 * @param variant_ The Base64 variant (default: Original).
 * @return C_ The decoded binary data.
 *
 * @par Note:
 *      This overload exists to allow passing sylvite::types::String directly.
 *      It works identically to the string_view overload.
 */
template<sylvite::concepts::Container C_ = std::vector<std::uint8_t>>
[[nodiscard]]
inline C_ decode(sylvite::types::String& view_, Variant variant_ = Variant::Original) {
    std::size_t max_bin_len_ = (view_.size() / 4) * 3 + 2;

    C_ b_(max_bin_len_);
    std::size_t fsz_;

    int result = sodium_base642bin(
        reinterpret_cast<unsigned char*>(b_.data()), b_.size(),
        view_.data(), view_.size(),
        nullptr, &fsz_, nullptr,
        static_cast<int>(variant_)
    );

    if (result != 0) {
        throw sylvite::exceptions::SodiumDecodificationError("Base64 decodification failed.");
    }

    b_.resize(fsz_);
    return b_;
}

} // namespace Base64

namespace Hex {

/**
 * @brief Encode binary data to a lowercase Hex string.
 *
 * @param data_ The binary data to encode.
 * @return std::string The lowercase hexadecimal string (e.g., "deadbeef").
 *
 * @par Output size:
 *      Output length is exactly `data_.size() * 2` characters.
 *
 * @par Example:
 * @code
 * auto hex = sylvite::utils::Hex::encode(hash);
 * std::cout << "SHA-256: " << hex << '\n';
 * @endcode
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::string encode(const T& data_) {
    std::string out_(data_.size() * 2 + 1, '\0');

    sodium_bin2hex(
        out_.data(), out_.size(),
        data_.data(), data_.size()
    );

    if (!out_.empty() && out_.back() == '\0') {
        out_.pop_back();
    }
    return out_;
}

/**
 * @brief Decode a Hex string to binary data.
 *
 * @tparam C_ The output container type (default: std::vector<std::uint8_t>).
 * @param view_ The hexadecimal string to decode (case-insensitive).
 * @return C_ The decoded binary data.
 *
 * @throw SodiumDecodificationError if the input is not valid hexadecimal.
 *
 * @par Case insensitivity:
 *      Both uppercase and lowercase hex digits are accepted.
 *      Odd-length input is not permitted (each byte needs 2 hex digits).
 *
 * @par Example:
 * @code
 * auto data = sylvite::utils::Hex::decode<std::vector<std::uint8_t>>("DEADBEEF");
 * @endcode
 */
template<sylvite::concepts::Container C_ = std::vector<std::uint8_t>>
[[nodiscard]]
inline C_ decode(std::string_view view_) {
    C_ b_(view_.size() / 2);
    std::size_t fsz_;

    int result_ = sodium_hex2bin(
        reinterpret_cast<unsigned char*>(b_.data()), b_.size(),
        view_.data(), view_.size(),
        nullptr, &fsz_, nullptr
    );

    if (result_ != 0) {
        throw sylvite::exceptions::SodiumDecodificationError("Hex decodification failed.");
    }

    b_.resize(fsz_);
    return b_;
}

} // namespace Hex

} // namespace sylvite::utils

#endif
