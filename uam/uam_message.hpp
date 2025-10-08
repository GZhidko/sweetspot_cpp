#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace uam {

inline constexpr std::size_t kMaxArgs = 32;
inline constexpr std::size_t kMaxArgSize = 32;
inline constexpr std::size_t kMaxMessageSize = 512;

struct ParsedMessage {
    std::optional<int> serial;
    std::optional<int> state_id;
    std::vector<std::string> arguments; // event + ip + payload args
};

// Encodes argv-style message into a null-delimited buffer.
// Throws std::runtime_error on overflow or invalid data.
std::string build_message(const std::vector<std::string>& argv);

// Decodes a buffer produced by build_message (or legacy UAM messages).
// Returns ParsedMessage with optional serial/state_id stripped off the front
// when the first argument is numeric. Throws std::runtime_error on parse errors.
ParsedMessage parse_message(std::string_view buffer);

} // namespace uam

