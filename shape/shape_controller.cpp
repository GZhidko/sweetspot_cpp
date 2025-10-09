#include "shape_controller.hpp"

#include "../common/worker.hpp"

#include <algorithm>
#include <chrono>

namespace shape {

ShapeController::ShapeController(Worker& owner) : owner_(owner) {
    thread_ = std::thread(&ShapeController::worker_loop, this);
}

ShapeController::~ShapeController() { shutdown(); }

void ShapeController::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
    }
    cv_.notify_all();
    if (thread_.joinable()) {
        thread_.join();
    }
}

void ShapeController::enqueue(Target target, std::vector<uint8_t>&& frame, size_t net_offset,
                              int rate_kbps) {
    if (!running_) {
        owner_.enqueue_shaped_frame(target == Target::Private ? Worker::InterfaceKind::Private
                                                              : Worker::InterfaceKind::Public,
                                   std::move(frame), net_offset);
        return;
    }

    if (rate_kbps <= 0) {
        owner_.enqueue_shaped_frame(target == Target::Private ? Worker::InterfaceKind::Private
                                                              : Worker::InterfaceKind::Public,
                                   std::move(frame), net_offset);
        return;
    }

    const uint64_t bits = static_cast<uint64_t>(frame.size()) * 8ULL;
    const uint64_t rate_bps = static_cast<uint64_t>(rate_kbps) * 1000ULL;
    std::chrono::nanoseconds delay_ns{0};
    if (rate_bps > 0) {
        const uint64_t numerator = bits * 1000000000ULL;
        if (numerator >= rate_bps) {
            delay_ns = std::chrono::nanoseconds(numerator / rate_bps);
        }
    }

    auto now = Clock::now();

    std::unique_lock<std::mutex> lock(mutex_);
    auto& next_ready = next_ready_by_rate_[rate_kbps];
    if (next_ready == Clock::time_point{}) {
        next_ready = now;
    }
    auto send_at = std::max(now, next_ready);
    next_ready = send_at + delay_ns;

    queue_.push(PendingFrame{target, std::move(frame), net_offset, send_at, rate_kbps});
    lock.unlock();
    cv_.notify_all();
}

void ShapeController::worker_loop() {
    while (true) {
        PendingFrame frame;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [&] { return !running_ || !queue_.empty(); });
            if (!running_ && queue_.empty()) {
                break;
            }

            auto now = Clock::now();
            auto& top = queue_.top();
            if (top.send_at > now) {
                cv_.wait_until(lock, top.send_at);
                if (!running_) {
                    continue;
                }
                if (queue_.empty()) {
                    continue;
                }
            }

            frame = std::move(const_cast<PendingFrame&>(queue_.top()));
            queue_.pop();
        }

        owner_.enqueue_shaped_frame(frame.target == Target::Private ? Worker::InterfaceKind::Private
                                                                    : Worker::InterfaceKind::Public,
                                    std::move(frame.buffer), frame.net_offset);
    }
}

} // namespace shape
