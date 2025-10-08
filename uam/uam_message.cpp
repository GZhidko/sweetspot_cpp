#include "uam_message.hpp"

#include <array>
#include <cstring>
#include <stdexcept>

namespace uam {
namespace {

bool is_numeric(std::string_view text) {
    if (text.empty()) {
        return false;
    }
    for (char ch : text) {
        if (ch < '0' || ch > '9') {
            return false;
        }
    }
    return true;
}

} // namespace

std::string build_message(const std::vector<std::string>& argv) {
    if (argv.size() >= kMaxArgs) {
        throw std::runtime_error("UAM argv overflow");
    }

    std::string buffer;
    buffer.resize(kMaxMessageSize);
    std::size_t offset = 0;

    for (const auto& arg : argv) {
        if (arg.size() >= kMaxArgSize) {
            throw std::runtime_error("UAM argument too long");
        }
        const std::size_t required = arg.size() + 1; // include delimiter
        if (offset + required > kMaxMessageSize) {
            throw std::runtime_error("UAM message too large");
        }
        std::memcpy(buffer.data() + offset, arg.data(), arg.size());
        buffer[offset + arg.size()] = '\0';
        offset += required;
    }

    buffer.resize(offset);
    return buffer;
}

ParsedMessage parse_message(std::string_view buffer) {
    if (buffer.size() >= kMaxMessageSize) {
        throw std::runtime_error("UAM message too large");
    }

    ParsedMessage result;
    std::vector<std::string> args;
    args.reserve(kMaxArgs);

    std::size_t pos = 0;
    while (pos < buffer.size()) {
        const char* ptr = buffer.data() + pos;
        std::size_t len = std::strlen(ptr);
        if (len >= kMaxArgSize) {
            throw std::runtime_error("UAM argument too long");
        }
        args.emplace_back(ptr, len);
        pos += len + 1;
    }

    if (!args.empty() && is_numeric(args.front())) {
        result.serial = std::stoi(args.front());
        args.erase(args.begin());
        if (!args.empty() && is_numeric(args.front())) {
            result.state_id = std::stoi(args.front());
            args.erase(args.begin());
        }
    }

    result.arguments = std::move(args);
    return result;
}

} // namespace uam

