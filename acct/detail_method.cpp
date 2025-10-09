#include "detail_method.hpp"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

#include "../common/logger.h"

namespace accounting {

void DetailMethod::set_output_path(std::string path) {
    LOG(DEBUG_ACCT, "detail set_output_path old=", path_, " new=", path);
    path_ = std::move(path);
}

bool DetailMethod::commit(AccountingEntry& entry, std::chrono::steady_clock::time_point now,
                          std::chrono::seconds delay) {
    if (path_.empty()) {
        return true;
    }

    auto now_sys = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now_sys);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &tt);
#else
    localtime_r(&tt, &tm_buf);
#endif
    char time_buf[64];
    std::strftime(time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Y\n", &tm_buf);

    std::string record(time_buf);
    for (const auto& scope : entry.scopes) {
        if (!scope) {
            continue;
        }
        scope->append_detail(record, delay);
    }
    record.push_back('\n');

    LOG(DEBUG_ACCT, "detail commit path=", path_, " pretty=", entry.pretty(),
        " delay=", delay.count(), "s");
    std::lock_guard<std::mutex> lock(io_mutex_);
    std::ofstream out(path_, std::ios::out | std::ios::app | std::ios::binary);
    if (!out.is_open()) {
        LOG(DEBUG_ACCT, "detail open failed path=", path_);
        return false;
    }
    out << record;
    if (!out.good()) {
        LOG(DEBUG_ACCT, "detail write failed path=", path_);
        return false;
    }
    LOG(DEBUG_ACCT, "detail commit success bytes=", record.size());
    return true;
}

} // namespace accounting
