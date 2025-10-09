#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <vector>

class Worker;

namespace shape {

class ShapeController {
  public:
    enum class Target { Private, Public };

    explicit ShapeController(Worker& owner);
    ~ShapeController();

    ShapeController(const ShapeController&) = delete;
    ShapeController& operator=(const ShapeController&) = delete;

    void enqueue(Target target, std::vector<uint8_t>&& frame, size_t net_offset, int rate_kbps);
    void shutdown();

  private:
    using Clock = std::chrono::steady_clock;

    struct PendingFrame {
        Target target;
        std::vector<uint8_t> buffer;
        size_t net_offset = 0;
        Clock::time_point send_at{};
        int rate_kbps = 0;
    };

    struct Compare {
        bool operator()(const PendingFrame& lhs, const PendingFrame& rhs) const {
            return lhs.send_at > rhs.send_at;
        }
    };

    void worker_loop();

    Worker& owner_;
    std::priority_queue<PendingFrame, std::vector<PendingFrame>, Compare> queue_;
    std::unordered_map<int, Clock::time_point> next_ready_by_rate_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_ = true;
    std::thread thread_;
};

} // namespace shape
