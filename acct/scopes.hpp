#pragma once

#include "gauge_tracker.hpp"
#include "snat_tracker.hpp"
#include "types.hpp"
#include "../sessions/session.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace accounting {

class Scope {
  public:
    virtual ~Scope() = default;
    virtual void append_detail(std::string& buffer, std::chrono::seconds delay) const = 0;
    virtual std::string pretty() const = 0;
};

using ScopeList = std::vector<std::unique_ptr<Scope>>;

class EventScope : public Scope {
  public:
    EventScope(RecordType type, std::chrono::system_clock::time_point timestamp,
               std::string event_context);

    void append_detail(std::string& buffer, std::chrono::seconds delay) const override;
    std::string pretty() const override;

  private:
    RecordType type_;
    std::chrono::system_clock::time_point timestamp_;
    std::string event_context_;
};

class SessionScope : public Scope {
  public:
    SessionScope(const sessions::Session& session, RecordType type);

    void append_detail(std::string& buffer, std::chrono::seconds delay) const override;
    std::string pretty() const override;

  private:
    RecordType type_;
    uint32_t ip_ = 0;
    uint32_t session_id_ = 0;
    sessions::TerminationCause termination_cause_ = sessions::TerminationCause::None;
    std::string session_context_;
    std::string filter_name_;
};

class GaugeScope : public Scope {
  public:
    GaugeScope(GaugeTracker::Snapshot snapshot, RecordType type);

    void append_detail(std::string& buffer, std::chrono::seconds delay) const override;
    std::string pretty() const override;

  private:
    GaugeTracker::Snapshot snapshot_;
    RecordType type_;
};

class SnatScope : public Scope {
  public:
    explicit SnatScope(SnatTracker::Snapshot snapshot);

    void append_detail(std::string& buffer, std::chrono::seconds delay) const override;
    std::string pretty() const override;

  private:
    SnatTracker::Snapshot snapshot_;
};

} // namespace accounting
