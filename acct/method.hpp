#pragma once

#include <chrono>
#include <cstdint>

namespace accounting {

struct AccountingEntry;

class Method {
  public:
    virtual ~Method() = default;

    void set_mask(uint32_t mask) { mask_ = mask; }
    uint32_t mask() const { return mask_; }

    virtual const char* name() const = 0;
    virtual bool commit(AccountingEntry& entry, std::chrono::steady_clock::time_point now,
                        std::chrono::seconds delay) = 0;

  private:
    uint32_t mask_ = 0;
};

} // namespace accounting
