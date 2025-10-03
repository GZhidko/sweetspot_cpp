#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace filters {

enum class Direction : uint8_t { Inbound = 0, Outbound = 1 };

enum class ActionFlag : uint8_t {
    Pass = 0x01,
    Block = 0x02,
    Dnat = 0x04,
    Shape = 0x08
};

inline constexpr ActionFlag operator|(ActionFlag lhs, ActionFlag rhs) {
    return static_cast<ActionFlag>(static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
}

inline constexpr ActionFlag& operator|=(ActionFlag& lhs, ActionFlag rhs) {
    lhs = lhs | rhs;
    return lhs;
}

inline constexpr bool has_flag(ActionFlag flags, ActionFlag needle) {
    return (static_cast<uint8_t>(flags) & static_cast<uint8_t>(needle)) != 0;
}

struct PacketState {
    Direction direction = Direction::Outbound;
    bool has_ipv4 = false;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint8_t protocol = 0;
    bool has_l4 = false;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    bool tcp_flags_valid = false;
    uint8_t tcp_flags = 0;
};

struct DnatTarget {
    uint32_t ip = 0;   // host order
    uint16_t port = 0; // host order
    bool valid = false;
};

struct Decision {
    bool matched = false;
    bool allow = true;
    ActionFlag actions = ActionFlag::Pass;
    DnatTarget dnat;
    int shape_rate = 0;
    uint32_t rule_index = 0;
};

class Engine {
  public:
    struct IpCondition {
        bool any = true;
        uint32_t network = 0;
        uint32_t mask = 0xFFFFFFFFu;

        bool matches(uint32_t ip) const { return any || ((ip & mask) == network); }
    };

    struct PortCondition {
        enum class Type { Any, Eq, Ne, Lt, Le, Gt, Ge, Range };

        Type type = Type::Any;
        std::vector<uint16_t> values;
        uint16_t threshold = 0;
        uint16_t range_lo = 0;
        uint16_t range_hi = 0;

        bool matches(uint16_t port) const;
        bool is_active() const;
    };

    struct Rule {
        ActionFlag actions = ActionFlag::Pass;
        uint8_t dir_mask = 0x03;
        std::optional<uint8_t> proto;
        IpCondition src_ip;
        IpCondition dst_ip;
        PortCondition src_ports;
        PortCondition dst_ports;
        bool src_requires_l4 = false;
        bool dst_requires_l4 = false;
        bool requires_l4 = false;
        uint8_t flags_set = 0;
        uint8_t flags_mask = 0;
        DnatTarget dnat;
        int shape_rate = 0;
        uint32_t index = 0;
    };

    static Engine& instance();

    void set_config_path(const std::string& path);
    void load_filter(const std::string& name, const std::filesystem::path& path);
    void load_directory(const std::filesystem::path& dir, bool recursive = false);
    void reload();

    Decision evaluate(const PacketState& state) const;
    Decision evaluate(const PacketState& state, const std::string& filter_name) const;

    std::size_t rule_count() const;
    std::size_t rule_count(const std::string& filter_name) const;
    std::vector<std::string> list_filters() const;
    std::string default_filter_name() const;

  private:
    Engine();

    struct FilterSet {
        std::vector<Rule> rules;
        std::filesystem::path source;
    };

    Decision evaluate_rules(const PacketState& state, const std::vector<Rule>& rules) const;
    std::vector<Rule> parse_file(const std::filesystem::path& path) const;
    static std::string derive_name_from_path(const std::filesystem::path& path);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, FilterSet> filters_;
    mutable std::string default_filter_;
    mutable std::filesystem::path default_path_;
};

} // namespace filters
