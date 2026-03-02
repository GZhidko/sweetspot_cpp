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
#include <array>
#include <algorithm>
#include <cctype>

// Флаги дебага
enum DebugFlags : uint32_t {
    DEBUG_NETSET   = 1 << 0,
    DEBUG_PARSER   = 1 << 1,
    DEBUG_NAT      = 1 << 2,
    DEBUG_ERROR    = 1 << 3,
    DEBUG_IO       = 1 << 4,
    DEBUG_SESSION  = 1 << 5,
    DEBUG_UAM      = 1 << 6,
    DEBUG_ACCT     = 1 << 7,
    DEBUG_FILTER   = 1 << 8,
    DEBUG_RELAY    = 1 << 9,
    DEBUG_ALL    = 0xFFFFFFFF
};

// Цвета ANSI
inline const char* colorForFlag(uint32_t flag) {
    switch (flag) {
        case DEBUG_NETSET:   return "\033[36m"; // cyan
        case DEBUG_PARSER:   return "\033[32m"; // green
        case DEBUG_NAT:      return "\033[35m"; // magenta
        case DEBUG_IO:       return "\033[33m"; // yellow
        case DEBUG_SESSION:  return "\033[34m"; // blue
        case DEBUG_UAM:      return "\033[90m"; // bright gray
        case DEBUG_ACCT:     return "\033[94m"; // bright blue
        case DEBUG_FILTER:   return "\033[92m"; // bright green
        case DEBUG_RELAY:    return "\033[95m"; // bright magenta
        case DEBUG_ERROR:    return "\033[31m"; // red
        default:           return "\033[0m";  // reset
    }
}

class Logger {
public:
    struct DebugName {
        const char* name;
        uint32_t bit;
    };

    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    static void setFlags(uint32_t flags) {
        instance().flags_ = flags;
    }

    static std::string debug_keywords() {
        std::ostringstream oss;
        const auto& names = debug_name_map();
        for (std::size_t i = 0; i < names.size(); ++i) {
            if (i != 0) {
                oss << ',';
            }
            oss << names[i].name;
        }
        return oss.str();
    }

    static bool parse_flags_spec(const std::string& spec, uint32_t& out_flags,
                                 std::string* error = nullptr) {
        const auto trimmed = trim_copy(spec);
        if (trimmed.empty()) {
            if (error) {
                *error = "empty debug spec";
            }
            return false;
        }

        // Numeric mask support: --debug 0x1f or --debug 255
        {
            std::size_t consumed = 0;
            try {
                const unsigned long parsed = std::stoul(trimmed, &consumed, 0);
                if (consumed == trimmed.size()) {
                    out_flags = static_cast<uint32_t>(parsed);
                    return true;
                }
            } catch (...) {
                // fall through to keyword parser
            }
        }

        uint32_t flags = 0;
        std::size_t start = 0;
        while (start <= trimmed.size()) {
            const std::size_t comma = trimmed.find(',', start);
            const std::string token =
                trim_copy(trimmed.substr(start, comma == std::string::npos
                                                     ? std::string::npos
                                                     : comma - start));
            if (token.empty()) {
                if (error) {
                    *error = "empty token in debug spec";
                }
                return false;
            }
            const std::string lowered = to_lower_copy(token);
            bool matched = false;
            for (const auto& entry : debug_name_map()) {
                if (lowered == entry.name) {
                    matched = true;
                    if (entry.bit == DEBUG_ALL) {
                        flags = DEBUG_ALL;
                    } else {
                        flags |= entry.bit;
                    }
                    break;
                }
            }
            if (!matched) {
                if (error) {
                    *error = "unknown debug keyword '" + token + "'";
                }
                return false;
            }

            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }

        out_flags = flags;
        return true;
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

    static std::string trim_copy(const std::string& text) {
        const auto begin = text.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos) {
            return {};
        }
        const auto end = text.find_last_not_of(" \t\r\n");
        return text.substr(begin, end - begin + 1);
    }

    static std::string to_lower_copy(const std::string& text) {
        std::string lowered = text;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return lowered;
    }

    static const std::array<DebugName, 15>& debug_name_map() {
        static const std::array<DebugName, 15> kNames{{
            {"none", 0},
            {"netset", DEBUG_NETSET},
            {"parser", DEBUG_PARSER},
            {"nat", DEBUG_NAT},
            {"io", DEBUG_IO},
            {"session", DEBUG_SESSION},
            {"uam", DEBUG_UAM},
            {"acct", DEBUG_ACCT},
            {"filter", DEBUG_FILTER},
            {"relay", DEBUG_RELAY},
            {"error", DEBUG_ERROR},
            {"snat", DEBUG_NAT},
            {"dnat", DEBUG_NAT},
            {"all", DEBUG_ALL},
            {"debug_all", DEBUG_ALL},
        }};
        return kNames;
    }

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
