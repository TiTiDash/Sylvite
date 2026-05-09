/**
 * @file box.hpp
 * @brief Asymmetric encryption: Box, SealedBox, and Ed25519 signatures.
 *
 * Provides three asymmetric cryptographic constructions:
 *
 * 1. **Box** (crypto_box): Ephemeral sender + recipient key pair.
 *    - Sender generates an ephemeral key pair, encrypts, and discards it.
 *    - Recipient's public key is used for encryption.
 *    - Recipient uses their private key + sender's public key to decrypt.
 *    - Provides forward secrecy (ephemeral key is discarded).
 *
 * 2. **SealedBox** (crypto_box_seal): Anonymized encryption to a key pair.
 *    - Only the recipient's public key is needed for encryption.
 *    - The ciphertext does not reveal who the sender is.
 *    - Recipient needs their private key to decrypt.
 *    - No forward secrecy.
 *
 * 3. **Ed25519 Signatures** (crypto_sign): Digital signatures.
 *    - Sign a message with a private key.
 *    - Anyone with the public key can verify the signature.
 *    - Ed25519 provides ~128-bit security and is resistant to
 *      side-channel attacks.
 *
 * @par Security pitfalls — common mistakes to avoid:
 * - **DON'T use Box for long-term encrypted communication without a ratchet** —
 *   Box provides forward secrecy but not post-compromise security. If an attacker
 *   records ciphertexts and later steals a private key, they can decrypt everything.
 *   For ongoing conversations, use a proper ratchet (Signal-style double ratchet).
 * - **DON'T use SealedBox when you need forward secrecy** — SealedBox does NOT provide
 *   forward secrecy because no ephemeral key is used. The ciphertext reveals who the
 *   recipient is, but nothing about the sender. Use Box if you need forward secrecy.
 * - **DON'T use the same key pair for both signing and encryption** — Ed25519 signing
 *   keys and Curve25519 encryption keys are incompatible curves. Use separate key
 *   pairs for each purpose.
 * - **DON'T ignore signature verification errors** — Always verify signatures before
 *   acting on a signed message. An invalid signature could mean the message was
 *   tampered with or signed by an attacker.
 * - **DON'T use Ed25519 public keys as Curve25519 public keys or vice versa** —
 *   They use different curves. Mixing them up will cause decryption/verification failures.
 *
 * @par Algorithm details:
 * - Box/SealedBox use Curve25519 for key exchange + XSalsa20-Poly1305 for encryption
 * - Ed25519 uses a Twisted Edwards curve (separate from Curve25519)
 * - Box uses ECDH (Elliptic Curve Diffie-Hellman) to derive a shared secret
 *
 * @par Example — Box:
 * @code
 * auto sender_kp = sylvite::asymmetric::crypto_generate_keypair();
 * auto recipient_kp = sylvite::asymmetric::crypto_generate_keypair();
 *
 * // Sender encrypts using recipient's public key + sender's private key
 * auto ct = sylvite::asymmetric::Box::encrypt(
 *     msg, recipient_kp.public_key, sender_kp.private_key
 * );
 *
 * // Recipient decrypts using sender's public key + recipient's private key
 * auto pt = sylvite::asymmetric::Box::decrypt(
 *     ct, sender_kp.public_key, recipient_kp.private_key
 * );
 * @endcode
 *
 * @par Example — SealedBox:
 * @code
 * auto kp = sylvite::asymmetric::crypto_generate_keypair();
 *
 * // Encrypt — only needs recipient's public key
 * auto ct = sylvite::asymmetric::SealedBox::seal(data, kp.public_key);
 *
 * // Decrypt — needs recipient's key pair
 * auto pt = sylvite::asymmetric::SealedBox::open(ct, kp.private_key, kp.public_key);
 * @endcode
 *
 * @par Example — Ed25519 Sign:
 * @code
 * auto kp = sylvite::asymmetric::sign_generate_keypair();
 *
 * auto sig = sylvite::sign::sign(message, kp.private_key);
 * bool valid = sylvite::sign::verify(sig, message, kp.public_key);
 * @endcode
 */

#ifndef SYLVITE_ASYMMETRIC_BOX_HPP
#define SYLVITE_ASYMMETRIC_BOX_HPP

#include <cstdint>
#include <vector>
#include <span>

#include "../frsdef.hpp"
#include <sodium.h>
#include "../concepts.hpp"
#include "../internal/base.hpp"
#include "../internal/noncemodify.hpp"
#include "../types/publickey.hpp"
#include "../types/privatekey.hpp"
#include "../types/nonce.hpp"
#include "../types/ciphertext.hpp"
#include "../utils/topk.hpp"

namespace sylvite::asymmetric {

/**
 * @brief Box — authenticated encryption using ephemeral sender key pair.
 *
 * Provides forward-secret encryption between two parties. The sender
 * generates an ephemeral key pair, derives a shared secret via ECDH
 * with the recipient's public key, encrypts with that secret, and
 * discards the ephemeral key pair.
 *
 * @par Security properties:
 * - IND-CPA secure (if the shared secret is secure)
 * - Authenticated: only the holder of the recipient's private key can decrypt
 * - Forward secret: the ephemeral key is not stored after encryption
 *
 * @par Shared secret derivation:
 *      crypto_box_easy computes: HSalsa20(Salsa20(nonce, ECDH(sender_sk, recipient_pk)), nonce)
 *      This binds the nonce and key exchange to produce the final encryption key.
 */
class Box final {
    public:
    /**
     * @brief Encrypt a message to a recipient using Box.
     *
     * @tparam T ContiguousByteContainer type for the plaintext.
     *
     * @param plaintext_ The message to encrypt.
     * @param recipient_pk_ The recipient's 32-byte public key.
     * @param sender_sk_ The sender's 32-byte private key (ephemeral in typical usage).
     *
     * @return sylvite::types::CipherText The ciphertext: [ nonce (24) | MAC (16) | ciphertext ].
     *
     * @throw SodiumRuntimeError if encryption fails (should not occur with valid inputs).
     *
     * @par Typical usage:
     *      Sender generates an ephemeral key pair just for this message,
     *      then discards it after encryption. The recipient can decrypt
     *      using their own key pair and the sender's public key (which
     *      might be a long-term key or sent alongside the ciphertext).
     *
     * @par Example:
     * @code
     * auto ephemeral_kp = sylvite::asymmetric::crypto_generate_keypair();
     * auto ct = sylvite::asymmetric::Box::encrypt(
     *     message, recipient_kp.public_key, ephemeral_kp.private_key
     * );
     * @endcode
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    [[nodiscard]]
    static sylvite::types::CipherText encrypt(
        const T& plaintext_,
        const sylvite::types::PublicKey& recipient_pk_,
        const sylvite::types::PrivateKey& sender_sk_
    ) {
        sylvite::types::Nonce nonce_;
        nonce_.random_generate(crypto_box_NONCEBYTES);

        sylvite::types::CipherText out_(crypto_box_NONCEBYTES + crypto_box_MACBYTES + plaintext_.size());
        std::copy(nonce_.begin(), nonce_.end(), out_.begin());

        int res_ = crypto_box_easy(
            out_.data() + crypto_box_NONCEBYTES,
            reinterpret_cast<const unsigned char*>(plaintext_.data()), plaintext_.size(),
            nonce_.data(),
            recipient_pk_.data(),
            sender_sk_.data()
        );
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Box encryption failed.");
        return out_;
    }

    /**
     * @brief Decrypt a Box ciphertext.
     *
     * @tparam C The output container type (default: std::vector<std::uint8_t>).
     *
     * @param ciphertext_ The ciphertext: [ nonce (24) | MAC (16) | ciphertext ].
     * @param sender_pk_ The sender's 32-byte public key.
     * @param recipient_sk_ The recipient's 32-byte private key.
     *
     * @return C The decrypted plaintext.
     *
     * @throw SodiumRuntimeError if:
     * - Ciphertext is too short
     * - Decryption/authentication fails (wrong key, tampered ciphertext)
     *
     * @par Key ordering:
     *      The sender's public key and recipient's private key are used
     *      to derive the same shared secret that was used for encryption.
     *
     * @par Example:
     * @code
     * auto pt = sylvite::asymmetric::Box::decrypt<std::vector<std::uint8_t>>(
     *     ct, sender_pk, recipient_sk
     * );
     * @endcode
     */
    template<sylvite::concepts::Container C = std::vector<std::uint8_t>>
    [[nodiscard]]
    static C decrypt(
        const sylvite::types::CipherText& ciphertext_,
        const sylvite::types::PublicKey& sender_pk_,
        const sylvite::types::PrivateKey& recipient_sk_
    ) {
        if (ciphertext_.size() < crypto_box_NONCEBYTES + crypto_box_MACBYTES)
            throw sylvite::exceptions::SodiumRuntimeError("CipherText too short.");
        auto nonce_ptr_ = ciphertext_.data();
        auto ct_ptr_ = ciphertext_.data() + crypto_box_NONCEBYTES;
        std::size_t ct_len = ciphertext_.size() - crypto_box_NONCEBYTES;
        C out_(ct_len - crypto_box_MACBYTES);

        int res_ = crypto_box_open_easy(
            reinterpret_cast<unsigned char*>(out_.data()),
            ct_ptr_, ct_len,
            nonce_ptr_, sender_pk_.data(), recipient_sk_.data()
        );
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Box decryption/auth failed.");
        return out_;
    }
};

/**
 * @brief SealedBox — anonymous encryption to a recipient's public key.
 *
 * Encrypts a message using only the recipient's public key. The ciphertext
 * does not reveal the sender's identity (unlike Box). The recipient uses
 * their private key (and optionally public key) to decrypt.
 *
 * @par Use cases:
 * - When sender anonymity is desired
 * - When the sender can't maintain state for ephemeral keys
 * - When only the recipient's public key is available (no prior interaction)
 *
 * @par Security properties:
 * - IND-CPA secure
 * - Sender anonymous: ciphertext doesn't reveal who encrypted it
 * - NOT forward secret (no ephemeral key)
 *
 * @par How it works:
 *      SealedBox uses crypto_box_seal which:
 *      1. Generates an ephemeral key pair
 *      2. Computes ECDH between ephemeral private key and recipient public key
 *      3. Derives a shared secret and encrypts with XSalsa20-Poly1305
 *      4. The ephemeral public key is embedded in the ciphertext
 *
 * @par Example:
 * @code
 * auto kp = sylvite::asymmetric::crypto_generate_keypair();
 *
 * // Encrypt — only needs recipient's public key
 * auto ct = sylvite::asymmetric::SealedBox::seal(secret, kp.public_key);
 *
 * // Decrypt
 * auto pt = sylvite::asymmetric::SealedBox::open(ct, kp.private_key, kp.public_key);
 * @endcode
 */
class SealedBox final {
    public:
    /**
     * @brief Encrypt a message to the holder of a public key (sender anonymous).
     *
     * @tparam T ContiguousByteContainer type for the plaintext.
     *
     * @param plaintext_ The message to encrypt.
     * @param recipient_pk_ The recipient's 32-byte public key.
     *
     * @return sylvite::types::CipherText The ciphertext: [ ephemeral_pk (32) | sealed_ct (48+plaintext) ].
     *
     * @throw SodiumRuntimeError if sealing fails.
     *
     * @par Output size:
     *      ciphertext_size = crypto_box_SEALBYTES + plaintext_size
     *      = 48 + plaintext_size (SEALBYTES = 32 for ephemeral pk + 16 for MAC)
     *
     * @par Example:
     * @code
     * auto ct = SealedBox::seal(message, recipient.public_key);
     * @endcode
     */
    template<sylvite::concepts::ContiguousByteContainer T>
    [[nodiscard]]
    static sylvite::types::CipherText seal(
        const T& plaintext_,
        sylvite::types::PublicKey recipient_pk_
    ) {
        sylvite::types::CipherText out_(crypto_box_SEALBYTES + plaintext_.size());

        int res_ = crypto_box_seal(
            out_.data(),
            reinterpret_cast<const unsigned char*>(plaintext_.data()), plaintext_.size(),
            recipient_pk_.data()
        );
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Seal failed.");
        return out_;
    }

    /**
     * @brief Decrypt a SealedBox ciphertext.
     *
     * @tparam C The output container type (default: std::vector<std::uint8_t>).
     *
     * @param ciphertext_ The ciphertext from seal().
     * @param recipient_sk_ The recipient's 32-byte private key.
     * @param recipient_pk_ The recipient's 32-byte public key.
     *
     * @return C The decrypted plaintext.
     *
     * @throw SodiumRuntimeError if ciphertext is too short or decryption fails.
     *
     * @par Overload with recipient_pk_:
     *      Use this overload when you have the recipient's public key
     *      readily available (it is embedded in the ciphertext but
     *      extracting it costs computation, so passing it is an optimization).
     *
     * @par Example:
     * @code
     * auto pt = SealedBox::open<std::vector<std::uint8_t>>(
     *     ct, recipient_sk, recipient_pk
     * );
     * @endcode
     */
    template<sylvite::concepts::Container C = std::vector<std::uint8_t>>
    [[nodiscard]]
    static C open(
        const sylvite::types::CipherText& ciphertext_,
        const sylvite::types::PrivateKey& recipient_sk_,
        const sylvite::types::PublicKey& recipient_pk_
    ) {
        if (ciphertext_.size() < crypto_box_SEALBYTES)
            throw sylvite::exceptions::SodiumRuntimeError("CipherText too short for sealed box.");
        C out_(ciphertext_.size() - crypto_box_SEALBYTES);

        int res_ = crypto_box_seal_open(
            reinterpret_cast<unsigned char*>(out_.data()),
            ciphertext_.data(), ciphertext_.size(),
            recipient_pk_.data(),
            recipient_sk_.data()
        );
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Seal open failed.");
        return out_;
    }

    /**
     * @brief Decrypt a SealedBox ciphertext (derives public key from private key).
     *
     * @tparam C The output container type (default: std::vector<std::uint8_t>).
     *
     * @param ciphertext_ The ciphertext from seal().
     * @param recipient_sk_ The recipient's 32-byte private key.
     *
     * @return C The decrypted plaintext.
     *
     * @throw SodiumRuntimeError if ciphertext is too short or decryption fails.
     *
     * @par Note:
     *      This overload derives the public key from the private key
     *      using crypto_scalarmult_base. Use the two-argument open()
     *      if you have the public key already (avoids recomputation).
     *
     * @par Example:
     * @code
     * auto pt = SealedBox::open<std::vector<std::uint8_t>>(ct, recipient_sk);
     * @endcode
     */
    template<sylvite::concepts::Container C = std::vector<std::uint8_t>>
    [[nodiscard]]
    static C open(
        const sylvite::types::CipherText& ciphertext_,
        const sylvite::types::PrivateKey& recipient_sk_
    ) {
        if (ciphertext_.size() < crypto_box_SEALBYTES)
            throw sylvite::exceptions::SodiumRuntimeError("CipherText too short for sealed box.");
        auto pk_ = sylvite::utils::FromSkToPk::crypto(recipient_sk_);
        C out_(ciphertext_.size() - crypto_box_SEALBYTES);

        int res_ = crypto_box_seal_open(
            out_.data(),
            ciphertext_.data(), ciphertext_.size(),
            pk_.data(),
            recipient_sk_.data()
        );
        if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Seal open failed.");
        return out_;
    }
};

} // namespace sylvite::asymmetric

namespace sylvite::sign {

/**
 * @brief Create an Ed25519 detached signature over a message.
 *
 * @tparam T ContiguousByteContainer type for the message.
 *
 * @param msg_ The message to sign.
 * @param sk_ The 64-byte Ed25519 signing private key.
 *
 * @return std::vector<std::uint8_t> The 64-byte detached signature.
 *
 * @throw SodiumRuntimeError if signing fails.
 *
 * @par Signature format:
 *      Ed25519 signatures are 64 bytes. The signature does not contain
 *      the message — it's a detached signature that must be verified
 *      alongside the message.
 *
 * @par Example:
 * @code
 * auto sig = sylvite::sign::sign(message, signing_keypair.private_key);
 * @endcode
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline std::vector<std::uint8_t> sign(
    const T& msg_,
    sylvite::types::PrivateKey& sk_
) {
    std::vector<std::uint8_t> out_(crypto_sign_BYTES);

    int res_ = crypto_sign_detached(
        out_.data(), nullptr,
        reinterpret_cast<const unsigned char*>(msg_.data()), msg_.size(),
        sk_.data()
    );
    if (res_ != 0) throw sylvite::exceptions::SodiumRuntimeError("Sign failed.");
    return out_;
}

/**
 * @brief Verify an Ed25519 detached signature.
 *
 * @tparam T ContiguousByteContainer type for the message.
 *
 * @param sig_ The 64-byte signature to verify.
 * @param msg_ The message that was signed.
 * @param pk_ The 32-byte Ed25519 public key of the signer.
 *
 * @return bool Always true if no exception is thrown.
 *
 * @throw SodiumInvalidSignature if the signature is invalid.
 *
 * @par Return value:
 *      Returns true on success (signature is valid). Throws
 *      SodiumInvalidSignature if verification fails.
 *
 * @par Example:
 * @code
 * bool valid = sylvite::sign::verify(sig, message, signer_pk);
 * @endcode
 */
template<sylvite::concepts::ContiguousByteContainer T>
[[nodiscard]]
inline bool verify(
    std::span<std::uint8_t> sig_,
    const T& msg_,
    sylvite::types::PublicKey& pk_
) {
    int valid_ = crypto_sign_verify_detached(
        sig_.data(),
        reinterpret_cast<const unsigned char*>(msg_.data()), msg_.size(),
        pk_.data()
    );
    if (valid_ != 0) throw sylvite::exceptions::SodiumInvalidSignature("Invalid signature.");
    return true;
}

} // namespace sylvite::sign

#endif
