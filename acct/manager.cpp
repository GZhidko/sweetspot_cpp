#include "manager.hpp"

#include "gauge_tracker.hpp"
#include "scopes.hpp"
#include "snat_tracker.hpp"

#include "../common/logger.h"

namespace accounting {

Manager& Manager::instance() {
    static Manager mgr;
    return mgr;
}

Manager::Manager() {
    detail_method_ = std::make_unique<DetailMethod>();
    register_method(detail_method_.get());
}

void Manager::configure(const Config& config) {
    detail_method_->set_output_path(config.detail_file);
}

void Manager::submit(const sessions::Session& session, RecordType type,
                     const std::string& event_context) {
    AccountingEntry entry;
    entry.created = std::chrono::steady_clock::now();
    entry.scopes = build_scopes(session, type, event_context);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(std::move(entry));
    }

    LOG(DEBUG_ACCT, "acct submit ip=", session.ip, " type=", to_string(type));
}

void Manager::commit(bool final) {
    if (methods_mask_ == 0) {
        return;
    }

    std::deque<AccountingEntry> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending.swap(queue_);
    }

    if (pending.empty()) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    std::deque<AccountingEntry> incomplete;
    incomplete.swap(pending); // reuse container memory

    while (!incomplete.empty()) {
        AccountingEntry entry = std::move(incomplete.front());
        incomplete.pop_front();

        auto delay = std::chrono::duration_cast<std::chrono::seconds>(now - entry.created);
        for (auto* method : methods_) {
            if ((entry.committed_mask & method->mask()) != 0) {
                continue;
            }
            bool ok = method->commit(entry, now, delay);
            if (ok || final) {
                entry.committed_mask |= method->mask();
            }
        }

        if (entry.committed_mask != methods_mask_) {
            pending.push_back(std::move(entry));
        } else {
            LOG(DEBUG_ACCT, "acct entry committed pretty=", entry.pretty());
        }
    }

    if (!pending.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!pending.empty()) {
            queue_.push_front(std::move(pending.back()));
            pending.pop_back();
        }
    }
}

void Manager::reset_for_tests() {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.clear();
    detail_method_->set_output_path("");
}

void Manager::register_method(Method* method) {
    const uint32_t mask = 1u << static_cast<uint32_t>(methods_.size());
    method->set_mask(mask);
    methods_mask_ |= mask;
    methods_.push_back(method);
}

ScopeList Manager::build_scopes(const sessions::Session& session, RecordType type,
                                const std::string& event_context) const {
    ScopeList scopes;
    scopes.reserve(4);
    scopes.emplace_back(std::make_unique<EventScope>(type, std::chrono::system_clock::now(),
                                                     event_context));
    scopes.emplace_back(std::make_unique<SessionScope>(session, type));
    scopes.emplace_back(
        std::make_unique<GaugeScope>(GaugeTracker::instance().snapshot(session.ip), type));
    scopes.emplace_back(std::make_unique<SnatScope>(SnatTracker::instance().snapshot(session.ip)));
    return scopes;
}

} // namespace accounting
