#pragma once

#include "detail_method.hpp"
#include "entry.hpp"
#include "types.hpp"
#include "../sessions/session.hpp"

#include <deque>
#include <mutex>
#include <optional>
#include <vector>

namespace accounting {

struct Config {
    std::string detail_file;
};

class Manager {
  public:
    static Manager& instance();

    void configure(const Config& config);
    void submit(const sessions::Session& session, RecordType type, const std::string& event_context);
    void commit(bool final);

    void reset_for_tests();

  private:
    Manager();

    void register_method(Method* method);
    ScopeList build_scopes(const sessions::Session& session, RecordType type,
                           const std::string& event_context) const;

    mutable std::mutex mutex_;
    std::deque<AccountingEntry> queue_;
    std::vector<Method*> methods_;
    uint32_t methods_mask_ = 0;

    std::unique_ptr<DetailMethod> detail_method_;
};

} // namespace accounting
