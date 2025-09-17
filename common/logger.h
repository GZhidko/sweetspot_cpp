#pragma once
#include <iostream>
#include <sstream>
#include <string>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <thread>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <fstream>

// Флаги дебага
enum DebugFlags : uint32_t {
    DEBUG_NETSET = 1 << 0,
    DEBUG_PARSER = 1 << 1,
    DEBUG_NAT    = 1 << 2,
    DEBUG_ERROR  = 1 << 3,
    DEBUG_ALL    = 0xFFFFFFFF
};

// Цвета ANSI
inline const char* colorForFlag(uint32_t flag) {
    switch (flag) {
        case DEBUG_NETSET: return "\033[36m"; // cyan
        case DEBUG_PARSER: return "\033[32m"; // green
        case DEBUG_NAT:    return "\033[35m"; // magenta
        case DEBUG_ERROR:  return "\033[31m"; // red
        default:           return "\033[0m";  // reset
    }
}

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    static void setFlags(uint32_t flags) {
        instance().flags_ = flags;
    }
    static void setOutputFile(const std::string& filename) {
        std::lock_guard<std::mutex> lock(instance().mutex_);
        instance().ofs_.open(filename, std::ios::out | std::ios::app); // append mode
        instance().useFile_ = instance().ofs_.is_open();
    }
    template<typename... Args>
    static void log(uint32_t flag, const char* file, int line, const char* func, Args&&... args) {
        if (!(instance().flags_ & flag)) return;

        std::ostringstream oss;
        (oss << ... << std::forward<Args>(args));
        auto t = std::time(nullptr);
        std::string timeStr = std::ctime(&t); // Tue Aug  6 20:29:51 2024\n
        if (!timeStr.empty() && timeStr.back() == '\n') timeStr.pop_back(); // убираем \n

        std::ostringstream msg;
        msg << timeStr
            << " [" << std::this_thread::get_id() << "]"
            << file << ":" << line << " "
            << func << ": "
            << oss.str();
        instance().enqueue(flag, msg.str());
    }

    static void shutdown() {
        instance().running_ = false;
        instance().cv_.notify_all();
        if (instance().worker_.joinable())
            instance().worker_.join();
    }

private:
    Logger() : running_(true), worker_(&Logger::processQueue, this) {}
    ~Logger() { shutdown(); }

    void enqueue(uint32_t flag, std::string&& msg) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.emplace(flag, std::move(msg));
        }
        cv_.notify_one();
    }

    void processQueue() {
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [&]{ return !queue_.empty() || !running_; });

            while (!queue_.empty()) {
                auto [flag, msg] = std::move(queue_.front());
                queue_.pop();
                lock.unlock();

                if (useFile_ && ofs_.is_open()) {
                    ofs_ << msg << "\n";
                    ofs_.flush();
                } else {
                    std::cerr << colorForFlag(flag) << msg << "\033[0m" << "\n";
                }

                lock.lock();
            }
        }
    }

    uint32_t flags_ = DEBUG_ALL;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::pair<uint32_t,std::string>> queue_;
    std::atomic<bool> running_;
    std::thread worker_;

    std::ofstream ofs_;
    bool useFile_ = false;
};

// Макрос для удобства
#define LOG(flag, ...) Logger::log(flag, __FILE__, __LINE__, __func__, __VA_ARGS__)

