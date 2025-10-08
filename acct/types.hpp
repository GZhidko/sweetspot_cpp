#pragma once

#include <string>

namespace accounting {

enum class RecordType { Start = 0, Stop = 1, Interim = 2, StopTime = 3 };

std::string to_string(RecordType type);

} // namespace accounting
