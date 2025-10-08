#pragma once

#include "entry.hpp"
#include "method.hpp"

#include <mutex>
#include <optional>
#include <string>

namespace accounting {

class DetailMethod : public Method {
  public:
    void set_output_path(std::string path);
    const std::string& output_path() const { return path_; }

    bool commit(AccountingEntry& entry, std::chrono::steady_clock::time_point now,
                std::chrono::seconds delay) override;
    const char* name() const override { return "DETAIL"; }

  private:
    std::string path_;
    std::mutex io_mutex_;
};

} // namespace accounting
