#include "entry.hpp"

#include <sstream>

namespace accounting {

std::string AccountingEntry::pretty() const {
    std::ostringstream oss;
    bool first = true;
    for (const auto& scope : scopes) {
        if (!scope) {
            continue;
        }
        if (!first) {
            oss << ',';
        }
        oss << scope->pretty();
        first = false;
    }
    return oss.str();
}

} // namespace accounting
