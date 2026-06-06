#pragma once

// Canonical error + result types for the peelf_core API (ToDo.md P0-9 / C1).
//
// Every fallible core function returns Result<T>. On failure it carries an Error
// with a human-readable message and the source location where it was raised.
// Prefer make_error("...") over constructing std::unexpected by hand: it captures
// the call site automatically.

#include <expected>
#include <source_location>
#include <string>
#include <utility>

namespace peelf {

struct Error {
    std::string message;
    std::source_location location{};
};

template <class T>
using Result = std::expected<T, Error>;

// Build the error branch of a Result<T>, capturing the call site automatically.
// Usage:  return make_error("PE file too small for DOS header");
[[nodiscard]] inline std::unexpected<Error> make_error(
    std::string message,
    const std::source_location& location = std::source_location::current()) {
    return std::unexpected(Error{std::move(message), location});
}

} // namespace peelf
