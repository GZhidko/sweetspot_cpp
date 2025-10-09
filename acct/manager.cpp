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
    LOG(DEBUG_ACCT, "acct configure detail_file=", config.detail_file,
        " methods_registered=", methods_.size());
}

void Manager::submit(const sessions::Session& session, RecordType type,
                     const std::string& event_context) {
    AccountingEntry entry;
    entry.created = std::chrono::steady_clock::now();
    entry.scopes = build_scopes(session, type, event_context);
    LOG(DEBUG_ACCT, "acct submit ip=", session.ip, " type=", to_string(type),
        " scopes=", entry.scopes.size());

    {
        std::lock_guard<std::mutex> lock(mutex_);
        LOG(DEBUG_ACCT, "acct queue push ip=", session.ip, " type=", to_string(type),
            " queue_size_before=", queue_.size());
        queue_.push_back(std::move(entry));
    }
}

void Manager::commit(bool final) {
    if (methods_mask_ == 0) {
        LOG(DEBUG_ACCT, "acct commit skipped no_methods");
        return;
    }

    std::deque<AccountingEntry> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending.swap(queue_);
    }

    if (pending.empty()) {
        LOG(DEBUG_ACCT, "acct commit queue empty");
        return;
    }

    auto now = std::chrono::steady_clock::now();
    std::deque<AccountingEntry> incomplete;
    incomplete.swap(pending); // reuse container memory

    LOG(DEBUG_ACCT, "acct commit begin entries=", incomplete.size(), " final=", final);

    while (!incomplete.empty()) {
        AccountingEntry entry = std::move(incomplete.front());
        incomplete.pop_front();

        auto delay = std::chrono::duration_cast<std::chrono::seconds>(now - entry.created);
        LOG(DEBUG_ACCT, "acct commit entry pretty=", entry.pretty(), " delay=", delay.count(),
            "s");
        for (auto* method : methods_) {
            if ((entry.committed_mask & method->mask()) != 0) {
                continue;
            }
            LOG(DEBUG_ACCT, "acct commit method=", method->name());
            bool ok = method->commit(entry, now, delay);
            if (ok || final) {
                entry.committed_mask |= method->mask();
                LOG(DEBUG_ACCT, "acct method done mask=", method->mask());
            }
        }

        if (entry.committed_mask != methods_mask_) {
            LOG(DEBUG_ACCT, "acct entry deferred pretty=", entry.pretty(),
                " committed_mask=", entry.committed_mask, " expected_mask=", methods_mask_);
            pending.push_back(std::move(entry));
        } else {
            LOG(DEBUG_ACCT, "acct entry committed pretty=", entry.pretty());
        }
    }

    if (!pending.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        LOG(DEBUG_ACCT, "acct requeue deferred entries=", pending.size());
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
    LOG(DEBUG_ACCT, "acct reset_for_tests");
}

void Manager::register_method(Method* method) {
    const uint32_t mask = 1u << static_cast<uint32_t>(methods_.size());
    method->set_mask(mask);
    methods_mask_ |= mask;
    methods_.push_back(method);
    LOG(DEBUG_ACCT, "acct register_method name=", method->name(), " mask=", mask,
        " total_methods=", methods_.size());
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
