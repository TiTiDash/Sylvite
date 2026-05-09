/**
 * @file noncemodify.hpp
 * @brief Internal utility for modifying Nonce state after use.
 *
 * Provides the NonceModify friend class that allows specific parts of the
 * library (XChaCha20Box) to mark a Nonce as "used" after encryption,
 * implementing a simple form of nonce reuse prevention at the API level.
 *
 * @note This is an internal header. Users should not need to include it directly.
 *
 * @internal
 * The Nonce class tracks whether it has been used via a `used_` flag.
 * After XChaCha20Poly1305::encrypt() successfully uses a nonce, it calls
 * NonceModify::modify() to set used_ = true, preventing accidental reuse
 * if the same Nonce object is passed to another encrypt call.
 */

#ifndef SYLVITE_NONCEMODIFY_HPP
#define SYLVITE_NONCEMODIFY_HPP

#include "../frsdef.hpp"

namespace sylvite::internal {

/**
 * @brief Friend class that can modify the internal state of a Nonce.
 *
 * Allows library-internal code to mark a Nonce as used after an encryption
 * operation completes, preventing the same Nonce from being accidentally
 * reused in subsequent encryptions.
 *
 * @par Why a friend class?
 *      The `used_` flag in Nonce is private, but we need symmetric
 *      crypto functions (specifically XChaCha20Box) to set it after
 *      successful encryption. Making NonceModify a friend avoids
 *      exposing a public setter while still allowing controlled access.
 *
 * @internal
 * Usage pattern:
 * ```
 * // Inside XChaCha20Poly1305::encrypt
 * sylvite::internal::NonceModify m;
 * m.modify(nonce_, true); // mark nonce as used
 * ```
 */
class NonceModify {
    public:
    /**
     * @brief Sets the used flag on a Nonce.
     *
     * @tparam M The Nonce generation mode (Lazy or Eager).
     * @param nonce_ The Nonce to modify.
     * @param state_ The boolean state to set (true = used, false = unused).
     *
     * @par Typical usage:
     *      After encrypt, state_ = true to mark as used and prevent reuse.
     *      The flag is reset by random_generate() or increment().
     */
    template<sylvite::types::Generation M>
    void modify(sylvite::types::Nonce<M>& nonce_, bool state_) {
        nonce_.used_ = state_;
    }
};

} // namespace sylvite::internal

#endif
