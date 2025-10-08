#include "types.hpp"

namespace accounting {

std::string to_string(RecordType type) {
    switch (type) {
    case RecordType::Start: return "Start";
    case RecordType::Stop: return "Stop";
    case RecordType::Interim: return "Interim";
    case RecordType::StopTime: return "StopTime";
    }
    return "Unknown";
}

} // namespace accounting
