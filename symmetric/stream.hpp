#ifndef SYLVITE_SYMMETRIC_STREAM_HPP
#define SYLVITE_SYMMETRIC_STREAM_HPP

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"
#include "../internal/noncemodify.hpp"
#include "../types/nonce.hpp"
#include "../types/streamheader.hpp"

namespace sylvite::symmetric::stream {

namespace XChaCha20Poly1305Stream {

class Encryptor final : public sylvite::internal::NonCopyable {
    sylvite::types::StreamHeader h_;
    crypto_secretstream_xchacha20poly1305_state state_;
    bool finalized_ = false;

public:
    explicit Encryptor(const sylvite::types::Key& key_) {
        if (key_.size() != crypto_secretstream_xchacha20poly1305_KEYBYTES) throw sylvite::exceptions::SodiumLogicError(
            "Key too short for XChaCha20Poly1305Stream: must be at least " +
            std::to_string(crypto_secretstream_xchacha20poly1305_KEYBYTES) + " bytes, but got "
            + std::to_string(key_.size())
        );
        crypto_secretstream_xchacha20poly1305_init_push(&state_, h_.data(), key_.data());
    }

    template<sylvite::concepts::ContiguousByteContainer T>
    [[nodiscard]]
    sylvite::types::CipherText update(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError(
            "Cannot push to a finalized stream.");
        sylvite::types::CipherText ct_(data_.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
        unsigned long long written_;
        if (crypto_secretstream_xchacha20poly1305_push(
            &state_, ct_.data(), &written_,
            data_.data(), data_.size(),
            nullptr, 0, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        ) != 0) throw sylvite::exceptions::SodiumRuntimeError("XChaCha20Poly1305Stream update failed.");
        return ct_;
    }

    template<sylvite::concepts::ContiguousByteContainer T>
    [[nodiscard]]
    sylvite::types::CipherText finalize(const T& data_) {
        if (finalized_) throw sylvite::exceptions::SodiumLogicError("Stream already finalized.");
        sylvite::types::CipherText ct_(data_.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
        unsigned long long written_;
        if (crypto_secretstream_xchacha20poly1305_push(
            &state_, ct_.data(), &written_,
            data_.data(), data_.size(),
            nullptr, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL
        ) != 0) throw sylvite::exceptions::SodiumRuntimeError("XChaCha20Poly1305Stream finalize failed.");
        finalized_ = true;
        return ct_;
    }

    sylvite::types::StreamHeader header() const noexcept {
        return sylvite::types::StreamHeader({h_.data(), h_.size()});
    }
};

} // namespace XChaCha20Poly1305

} // namespace sylvite::symmetric::stream

#endif