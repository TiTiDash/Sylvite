/**
 * @file frsdef.hpp
 * @brief Forward declarations for the Sylvite library.
 *
 * This file contains forward declarations for all types and namespaces,
 * allowing headers to reference each other without circular includes.
 * This is the foundation that breaks all circular dependency chains.
 *
 * @note This header is internal. Users should include sodium.hpp instead.
 */

#ifndef SYLVITE_FSRDEF_HPP
#define SYLVITE_FSRDEF_HPP

// Principal sylvite's namespace
namespace sylvite {} // namespace sylvite

// Forward-declare the Generation enum (defined in types/nonce.hpp)
namespace sylvite::types {
    enum class Generation : int;
}

// Exception types (namespace sylvite::exceptions)
namespace sylvite::exceptions {
    class sodium_exception;
    class SodiumInitError;
    class SodiumLogicError;
    class SodiumRuntimeError;
    class SodiumIndexError;
    class SodiumEmptyStringError;
    class SodiumDecodificationError;
    class SodiumDerivationError;
    class SodiumOutOfRangeError;
    class SodiumInvalidSignature;
}

// Internal types (namespace sylvite::internal)
namespace sylvite::internal {
    class NonCopyable;

    template<typename T, typename Alloc>
    class Base;

    template<typename T>
    struct s_alloc;

    class NonceModify;
}

// Core buffer types (namespace sylvite::types)
namespace sylvite::types {
    template<Generation M>
    class Nonce;

    class Key;
    class CipherText;
    class String;
    class Salt;
    class PublicKey;
    class PrivateKey;
    class StreamHeader;
}

// KEM types (namespace sylvite::kem)
namespace sylvite::kem {
    struct KeyPair;
}

namespace sylvite::kem::XWing {
    sylvite::kem::KeyPair generate_keypair();
}

namespace sylvite::kem::MlKem768 {
    sylvite::kem::KeyPair generate_keypair();
}

// Stream cipher types (namespace sylvite::symmetric::stream)
namespace sylvite::symmetric::stream::XChaCha20Poly1305Stream {
    class Encryptor;
    class Decryptor;
}

#endif
