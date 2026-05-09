/**
 * @file sylvite.hpp
 * @brief Sylvite — A header-only C++20 cryptography library wrapping libsodium.
 *
 * Sylvite provides a modern C++ interface to the libsodium cryptography library,
 * offering:
 * - **Symmetric encryption**: XChaCha20-Poly1305-IETF, XSalsa20-Poly1305 (authenticated)
 * - **Asymmetric encryption**: Curve25519 Box, SealedBox (IND-CPA secure)
 * - **Digital signatures**: Ed25519
 * - **Post-quantum KEM**: ML-KEM-768, X-Wing (hybrid)
 * - **Password hashing**: Argon2ID (memory-hard, winner of PHC)
 * - **Key derivation**: HKDF (from master key), Argon2ID (from password)
 * - **Hashing**: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b
 * - **HMAC**: HMAC-SHA-256, HMAC-SHA-512
 *
 * @par Requirements:
 * - C++20 or later
 * - libsodium 1.0.22 or later
 *
 * @par Include this header to get access to all Sylvite functionality:
 *      ```
 *      #include "sylvite.hpp"
 *      sylvite::ensure_init();
 *      ```
 *
 * @par Namespace organization:
 *      All types and functions live in the `sodium` namespace hierarchy:
 *      - `sylvite::` — initialization, utilities
 *      - `sylvite::types::` — Key, Nonce, Salt, CipherText, String, PrivateKey, PublicKey
 *      - `sylvite::symmetric::` — XChaCha20Poly1305, XChaCha20Box, XSalsa20Box
 *      - `sylvite::asymmetric::` — Box, SealedBox, crypto_generate_keypair, sign_generate_keypair
 *      - `sylvite::sign::` — sign, verify
 *      - `sylvite::kem::` — MlKem768, XWing
 *      - `sylvite::kdf::` — Argon2ID_derive_key, derive_subkey
 *      - `sylvite::hash::` — Sha256, Sha512, Sha3_256, Sha3_512, Blake2b
 *      - `sylvite::utils::` — Base64, Hex, console, random, Packer
 *
 * @par Example — symmetric encryption:
 *      ```
 *      sylvite::types::Key key(32);
 *      key.random_generate();
 *      sylvite::types::Nonce nonce;
 *      auto ct = sylvite::symmetric::XChaCha20Poly1305::encrypt(plaintext, key, nonce);
 *      auto pt = sylvite::symmetric::XChaCha20Poly1305::decrypt(ct, key, nonce);
 *      ```
 *
 * @par Example — password-based encryption:
 *      ```
 *      sylvite::types::Salt salt;
 *      salt.random_generate();
 *      auto key = sylvite::kdf::Argon2ID_derive_key(password, salt, 32);
 *      auto ct = sylvite::symmetric::XChaCha20Box::encrypt(data, key);
 *      ```
 */

#ifndef SYLVITE_SODIUM_HPP
#define SYLVITE_SODIUM_HPP

#if(defined(_MSVC_LANG)?_MSVC_LANG:__cplusplus)<202002L
#error "C++20 or later is required to use Sylvite"
#endif

#include <sodium.h>

#if SODIUM_LIBRARY_VERSION_MAJOR < 26
#error "Libsodium 1.0.22 or later is required to use Sylvite"
#endif

// ─────────────────────────────────────────────────────────────
// Foundation — forward declarations, no dependencies
// ─────────────────────────────────────────────────────────────
#include "frsdef.hpp"

// ─────────────────────────────────────────────────────────────
// Pure C++ — no sodium deps
// ─────────────────────────────────────────────────────────────
#include "exceptions/exceptions.hpp"
#include "concepts.hpp"
#include "init.hpp"

// ─────────────────────────────────────────────────────────────
// Internal — sodium.h + fwd decls only
// ─────────────────────────────────────────────────────────────
#include "internal/salloc.hpp"
#include "internal/base.hpp"
#include "internal/noncemodify.hpp"

// ─────────────────────────────────────────────────────────────
// Types — need internal/base, concepts
// ─────────────────────────────────────────────────────────────
#include "types/ciphertext.hpp"
#include "types/string.hpp"
#include "types/key.hpp"
#include "types/nonce.hpp"
#include "types/salt.hpp"
#include "types/publickey.hpp"
#include "types/privatekey.hpp"
#include "types/streamheader.hpp"

// ─────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────
#include "utils/utils.hpp"
#include "utils/console.hpp"
#include "utils/base64.hpp"
#include "utils/packer.hpp"
#include "utils/topk.hpp"

// ─────────────────────────────────────────────────────────────
// Crypto modules
// ─────────────────────────────────────────────────────────────
#include "symmetric/xchacha20.hpp"
#include "symmetric/xchacha20box.hpp"
#include "symmetric/xsalsa20box.hpp"
#include "symmetric/stream.hpp"
#include "asymmetric/box.hpp"
#include "asymmetric/keypair.hpp"
#include "kdf/argon2id.hpp"
#include "kdf/hkdf.hpp"
#include "hash/hash.hpp"
#include "hash/hmac.hpp"
#include "pq/kem.hpp"

#endif
