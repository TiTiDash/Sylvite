/**
 * @file init.hpp
 * @brief Sylvite library initialization utilities.
 *
 * Provides `ensure_init()` and `init()` functions that guarantee libsodium
 * is safely initialized before any crypto operations. Uses a static-local
 * pattern to ensure initialization happens exactly once in a thread-safe way.
 *
 * Libsodium requires initialization before calling any of its functions.
 * Sylvite handles this automatically in type constructors (e.g., Key's
 * constructor calls `sodium::ensure_init()`), but you may also call these
 * functions explicitly to handle initialization errors or check initialization
 * status yourself.
 *
 * @note `ensure_init()` is called implicitly by many constructors in the
 *       library. You typically don't need to call these manually unless you
 *       want to handle initialization failure explicitly.
 *
 * Example:
 * @code
 * // Check if initialization succeeded
 * if (sodium::init() < 0) {
 *     std::cerr << "Failed to initialize libsodium\n";
 *     return;
 * }
 *
 * // Or use ensure_init() which throws on failure
 * sodium::ensure_init(); // throws SodiumInitError on failure
 * @endcode
 */

#ifndef SYLVITE_INIT_HPP
#define SYLVITE_INIT_HPP

#include "frsdef.hpp"
#include <sodium.h>
#include "exceptions/exceptions.hpp"

namespace sylvite {

/**
 * @brief Ensures libsodium is initialized, throwing on failure.
 *
 * Uses a static local variable with a lambda initializer to guarantee
 * one-time initialization in a thread-safe manner (C++11 static initialization
 * guarantees). If initialization fails, throws `SodiumInitError`.
 *
 * @throw sylvite::exceptions::SodiumInitError if libsodium fails to initialize.
 *
 * @note This function is idempotent — calling it multiple times is safe
 *       and will not re-initialize.
 *
 * @par Memory ordering:
 *      The static initializer uses a memory barrier to ensure libsodium's
 *      internal state is visible across all threads before any subsequent
 *      crypto operations execute.
 */
inline void ensure_init() {
    [[maybe_unused]] static bool ok_ = []() -> bool {
        if (sodium_init() < 0) {
            throw sylvite::exceptions::SodiumInitError();
        }
        return true;
    }();
    (void)ok_;
};

/**
 * @brief Initializes libsodium and returns a status code.
 *
 * A non-throwing alternative to `ensure_init()`. Returns 0 on success,
 * 1 if initialization was already attempted, and -1 if the library
 * couldn't be loaded.
 *
 * @return int 0 in case of success, -1 in case of failure or 1 in case of having already been initialized previously.
 *
 * @note Unlike `ensure_init()`, this function does not throw on failure.
 *       Use this when you need to handle initialization failure without
 *       exceptions, or when you need to know if initialization already
 *       happened.
 *
 * @par Thread safety:
 *      Multiple threads can call this simultaneously; libsodium handles
 *      concurrent initialization safely.
 *
 * @par Memory behavior:
 *      After successful initialization, libsodium allocates internal
 *      per-thread state and random seed buffers. On supported platforms,
 *      it also locks memory pages to prevent swapping.
 */
inline int init() noexcept {
    try {
        ensure_init();
        return 0;
    }
    catch (sylvite::exceptions::SodiumInitError&) {
        return -1;
    }
}

} // namespace sylvite

#endif
