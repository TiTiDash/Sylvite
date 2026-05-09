#ifndef SYLVITE_STREAMHEADER_TYPE_HPP
#define SYLVITE_STREAMHEADER_TYPE_HPP

#include "../frsdef.hpp"
#include <sodium.h>
#include "../internal/base.hpp"

namespace sylvite::types {

class StreamHeader final : public sylvite::internal::Base<std::uint8_t>, public sylvite::internal::NonCopyable {
    using B_ = sylvite::internal::Base<std::uint8_t>;
    friend class sylvite::symmetric::stream::XChaCha20Poly1305Stream::Encryptor;
    explicit StreamHeader() : B_(crypto_secretstream_xchacha20poly1305_HEADERBYTES) {}

public:
    explicit StreamHeader(std::span<const std::uint8_t> bytes_) : B_(bytes_) {
        if (bytes_.size() != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
            throw sylvite::exceptions::SodiumLogicError(
                "Invalid StreamHeader size. Expected " +
                std::to_string(crypto_secretstream_xchacha20poly1305_HEADERBYTES) +
                " bytes, got " + std::to_string(bytes_.size())
            );
        }
    }
};

} // namespace sylvite::types

#endif