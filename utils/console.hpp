/**
 * @file console.hpp
 * @brief Console I/O utilities for secure input and screen control.
 *
 * Provides utilities for:
 * - Secure password input (with disabled echo)
 * - Console screen clearing (ANSI and system-dependent)
 * - Input stream cleanup
 *
 * @par Platform support:
 * - Windows: Uses Win32 API (GetStdHandle, SetConsoleMode, WriteConsoleInput)
 * - POSIX (Unix/Linux/macOS): Uses termios (tcgetattr, tcsetattr)
 *
 * @par Example:
 *      ```
 *      // Read a password without echoing
 *      auto password = sylvite::utils::console::read_from_console("Password: ");
 *
 *      // Clear the screen
 *      sylvite::utils::console::ANSIClear();
 *
 *      // Clear input stream
 *      sylvite::utils::console::CinClear(std::cin);
 *      ```
 */

#ifndef SYLVITE_CONSOLE_HPP
#define SYLVITE_CONSOLE_HPP

#include <iostream>
#include <cstdlib>
#include <limits>

#include "../frsdef.hpp"
#include "../init.hpp"

// Platform detection
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    #define SODIUMPP_ECHO_PLATFORM_WINDOWS
    #include <windows.h>
#elif defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
    #include <unistd.h>
    #if defined(_POSIX_VERSION)
        #define SODIUMPP_ECHO_PLATFORM_POSIX
        #include <termios.h>
    #else
        #error "Unix system detected, but does not meet the POSIX standard required for termios."
    #endif
#else
    #error "Unsupported platform. This class requires the Windows API or the POSIX standard."
#endif

namespace sylvite::utils::console {

/**
 * @brief RAII class that disables console echo for its lifetime.
 *
 * When a DisableEcho object is constructed, console echo is disabled
 * (typed characters are not shown). When the object is destroyed (exits
 * scope), console echo is restored automatically.
 *
 * @par Windows implementation:
 *      Uses SetConsoleMode to clear ENABLE_ECHO_INPUT flag on stdin.
 *      Restores the original mode on destruction. Also sends a FOCUS_EVENT
 *      to flush the console input buffer and restore normal behavior.
 *
 * @par POSIX implementation:
 *      Uses tcgetattr/tcsetattr to modify the ECHO flag in the terminal's
 *      termios structure. Restores the original settings on destruction.
 *
 * @par Usage:
 *      Create on the stack — when it goes out of scope, echo is restored:
 *      ```
 *      {
 *          DisableEcho no_echo; // echo disabled
 *          std::cin >> password;
 *      } // echo automatically restored here
 *      ```
 *
 * @par Thread safety:
 *      Not thread-safe. DisableEcho modifies global terminal state.
 *      Multiple threads interacting with the same terminal may
 *      interfere with each other.
 */
class DisableEcho {
#ifdef SODIUMPP_ECHO_PLATFORM_WINDOWS
    HANDLE hStdin;          ///< Windows console input handle.
    DWORD oldMode;           ///< Saved console mode (to restore on exit).
#else
    struct termios oldT;    ///< Saved terminal attributes (to restore on exit).
#endif
    bool success;            ///< Whether echo was successfully disabled.

public:
    /**
     * @brief Construct and immediately disable console echo.
     *
     * Attempts to disable echo for the current terminal.
     * Check isApplied() to confirm success.
     */
    DisableEcho() : success(false) {
#ifdef SODIUMPP_ECHO_PLATFORM_WINDOWS
        hStdin = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdin != INVALID_HANDLE_VALUE && GetConsoleMode(hStdin, &oldMode)) {
            DWORD newMode = oldMode & ~ENABLE_ECHO_INPUT;
            if (SetConsoleMode(hStdin, newMode)) {
                success = true;
            }
        }
#else
        if (isatty(STDIN_FILENO)) {
            if (tcgetattr(STDIN_FILENO, &oldT) == 0) {
                struct termios newT = oldT;
                newT.c_lflag &= ~ECHO;
                if (tcsetattr(STDIN_FILENO, TCSANOW, &newT) == 0) {
                    success = true;
                }
            }
        }
#endif
    }

    /// @brief Destructor — restores the original console echo state.
    ~DisableEcho() {
        if (success) {
#ifdef SODIUMPP_ECHO_PLATFORM_WINDOWS
            SetConsoleMode(hStdin, oldMode);
            INPUT_RECORD ir[1];
            DWORD written;
            ir[0].EventType = FOCUS_EVENT;
            ir[0].Event.FocusEvent.bSetFocus = TRUE;
            WriteConsoleInput(hStdin, ir, 1, &written);
#else
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldT);
#endif
        }
    }

    /// @brief Returns true if echo was successfully disabled.
    bool isApplied() const noexcept { return success; }

    // Non-copyable, non-movable
    DisableEcho(const DisableEcho&) = delete;
    DisableEcho& operator=(const DisableEcho&) = delete;
    DisableEcho(DisableEcho&&) = delete;
    DisableEcho& operator=(DisableEcho&&) = delete;
};

/**
 * @brief Read a password or sensitive input from the console without echoing.
 *
 * Disables console echo, reads characters until newline/carriage return,
 * and stores them in a sylvite::types::String. Echo is restored automatically
 * when the function returns (RAII DisableEcho).
 *
 * @param prompt_ Optional prompt to display before reading.
 * @return sylvite::types::String The input characters (不含 newline).
 *
 * @par Security:
 *      Characters are not echoed to the screen while typing.
 *      The returned String uses secure memory (locked, wiped on destruction).
 *
 * @par Newline handling:
 *      Both '\n' and '\r' are accepted as line terminators.
 *      The delimiter is not stored in the string.
 *
 * @par Example:
 *      ```
 *      auto password = sylvite::utils::console::read_from_console("Enter password: ");
 *      auto key = sylvite::kdf::Argon2ID_derive_key(password, salt, 32);
 *      password.wipe(); // explicitly wipe sensitive data
 *      ```
 */
[[nodiscard]] inline sylvite::types::String read_from_console(const char* prompt_ = nullptr) noexcept {
    if (prompt_) {
        std::cout << prompt_ << std::flush;
    }

    DisableEcho eg_; // RAII — echo disabled during this scope

    sylvite::types::String si_;
    char c_;

    while (std::cin.get(c_)) {
        if (c_ == '\n' || c_ == '\r') {
            break;
        }
        si_.push_back(c_);
    }

    return si_;
}

/**
 * @brief Clear the console screen using ANSI escape sequences.
 *
 * Uses the ANSI escape sequence ESC[2J ESC[3J ESC[H to clear the screen
 * and move the cursor to the home position. This works on most modern
 * terminals including xterm, ANSI.SYS on Windows (via conemu/msys), and
 * Linux consoles.
 *
 * @note This will not work on older Windows consoles (cmd.exe) that
 *       don't support ANSI escape sequences natively. Use SystemClear()
 *       for broader compatibility on Windows.
 *
 * @par Effect:
 *      After calling this, the terminal screen will be cleared and
 *      the cursor will be at position (1,1) / top-left.
 */
inline void ANSIClear() noexcept {
    std::cout << "\033[2J\033[3J\033[H";
}

/**
 * @brief Clear the console screen using a system call.
 *
 * Uses `system("cls")` on Windows or `system("clear")` on Unix.
 * This is slower than ANSIClear() but more widely compatible across
 * different terminal types, especially older Windows consoles.
 *
 * @warning Calling system() can have security implications if the
 *          terminal's locale or environment variables are attacker-controlled.
 *          Prefer ANSIClear() when possible.
 *
 * @par Platform behavior:
 *      - Windows: Calls `cls` via cmd.exe /c
 *      - Unix: Calls `clear` via /bin/sh
 */
inline void SystemClear() noexcept {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

/**
 * @brief Clear characters waiting in an input stream.
 *
 * Ignores (discards) all characters in the input stream up to and
 * including the specified delimiter. Commonly used to clear a stray
 * newline from std::cin after using operator>> for numeric input.
 *
 * @param cin_ The input stream to clear.
 * @param ign_ The delimiter character (default '\n').
 *
 * @par Use case:
 *      After reading with `std::cin >> x`, a trailing '\n' remains in
 *      the stream. If you then call getline(), it will read an empty
 *      line. Use CinClear to discard the leftover newline.
 *
 * @par Example:
 *      ```
 *      int choice;
 *      std::cin >> choice;
 *      sylvite::utils::console::CinClear(std::cin); // discard the newline
 *      std::string name;
 *      std::getline(std::cin, name); // works correctly now
 *      ```
 */
inline void CinClear(std::istream& cin_, char ign_ = '\n') noexcept {
    cin_.ignore(std::numeric_limits<std::streamsize>::max(), ign_);
}

} // namespace sylvite::utils

#endif
