#pragma once

#include "scopes.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace accounting {

struct AccountingEntry {
    ScopeList scopes;
    std::chrono::steady_clock::time_point created;
    uint32_t committed_mask = 0;

    std::string pretty() const;
};

} // namespace accounting
