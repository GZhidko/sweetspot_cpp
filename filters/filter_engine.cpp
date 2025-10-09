#include "filter_engine.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "../common/logger.h"

namespace filters {
namespace {

constexpr uint8_t DIR_IN_MASK = 0x01;
constexpr uint8_t DIR_OUT_MASK = 0x02;
constexpr std::size_t MAX_RULES = 512;
constexpr std::size_t MAX_PORTS = 8;

std::string ip_to_string(uint32_t ip_host) {
    in_addr addr{};
    addr.s_addr = htonl(ip_host);
    char buf[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "<invalid_ip>";
    }
    return buf;
}

std::string describe_packet_state(const PacketState& state) {
    std::ostringstream oss;
    oss << "dir=" << (state.direction == Direction::Inbound ? "in" : "out")
        << " ipv4=" << state.has_ipv4
        << " src=" << ip_to_string(state.src_ip)
        << " dst=" << ip_to_string(state.dst_ip)
        << " proto=" << static_cast<int>(state.protocol)
        << " l4=" << state.has_l4
        << " sport=" << state.src_port
        << " dport=" << state.dst_port;
    if (state.tcp_flags_valid) {
        oss << " flags=0x" << std::hex << std::uppercase << static_cast<int>(state.tcp_flags)
            << std::dec << std::nouppercase;
    }
    return oss.str();
}

uint8_t direction_to_mask(Direction dir) {
    return dir == Direction::Inbound ? DIR_IN_MASK : DIR_OUT_MASK;
}

std::string to_lower(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool is_ident_char(char ch) {
    unsigned char uch = static_cast<unsigned char>(ch);
    return std::isalnum(uch) || ch == '.' || ch == '-' || ch == '_' || ch == '*';
}

bool parse_ipv4(std::string_view token, uint32_t& ip_host) {
    if (token == "*" || to_lower(token) == "any") {
        return false;
    }
    in_addr addr{};
    std::string tmp(token);
    if (inet_pton(AF_INET, tmp.c_str(), &addr) != 1) {
        return false;
    }
    ip_host = ntohl(addr.s_addr);
    return true;
}

uint32_t prefix_to_mask(int prefix) {
    if (prefix <= 0) {
        return 0;
    }
    if (prefix >= 32) {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32 - prefix);
}

struct Token {
    enum class Type { Identifier, Number, Colon, Slash, Comma, EndOfLine, End, Error };

    Type type{Type::End};
    std::string text;
    uint32_t number = 0;
    std::size_t line = 0;
    std::size_t column = 0;
};

class Tokenizer {
  public:
    explicit Tokenizer(std::string content) : text_(std::move(content)) {}

    std::vector<Token> run() {
        std::vector<Token> tokens;
        while (pos_ < text_.size()) {
            char ch = text_[pos_];
            if (ch == '#') {
                skip_comment();
                continue;
            }
            if (ch == '\r') {
                advance();
                continue;
            }
            if (ch == '\n') {
                tokens.push_back(make_token(Token::Type::EndOfLine, "", 0));
                advance_line();
                continue;
            }
            if (std::isspace(static_cast<unsigned char>(ch))) {
                advance();
                continue;
            }
            if (std::isdigit(static_cast<unsigned char>(ch))) {
                if (looks_like_ipv4()) {
                    tokens.push_back(parse_identifier());
                } else {
                    tokens.push_back(parse_number());
                }
                continue;
            }
            if (is_ident_char(ch)) {
                tokens.push_back(parse_identifier());
                continue;
            }
            switch (ch) {
            case ':':
                tokens.push_back(make_token(Token::Type::Colon, ":", 0));
                advance();
                break;
            case '/':
                tokens.push_back(make_token(Token::Type::Slash, "/", 0));
                advance();
                break;
            case ',':
                tokens.push_back(make_token(Token::Type::Comma, ",", 0));
                advance();
                break;
            default:
                tokens.push_back(make_token(Token::Type::Error, std::string(1, ch), 0));
                advance();
                break;
            }
        }
        tokens.push_back(make_token(Token::Type::End, "", 0));
        return tokens;
    }

  private:
    Token make_token(Token::Type type, std::string text, uint32_t number) const {
        return Token{type, std::move(text), number, line_, column_};
    }

    void advance() {
        ++pos_;
        ++column_;
    }

    void advance_line() {
        ++pos_;
        ++line_;
        column_ = 1;
    }

    void skip_comment() {
        while (pos_ < text_.size() && text_[pos_] != '\n') {
            advance();
        }
    }

    bool looks_like_ipv4() const {
        std::size_t lookahead = pos_;
        bool has_dot = false;
        while (lookahead < text_.size()) {
            char ch = text_[lookahead];
            if (std::isdigit(static_cast<unsigned char>(ch))) {
                ++lookahead;
                continue;
            }
            if (ch == '.') {
                has_dot = true;
                ++lookahead;
                continue;
            }
            break;
        }
        return has_dot;
    }

    Token parse_identifier() {
        std::size_t start = pos_;
        while (pos_ < text_.size() && is_ident_char(text_[pos_])) {
            advance();
        }
        return make_token(Token::Type::Identifier, text_.substr(start, pos_ - start), 0);
    }

    Token parse_number() {
        std::size_t start = pos_;
        uint64_t value = 0;
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            value = value * 10 + static_cast<uint32_t>(text_[pos_] - '0');
            advance();
        }
        if (value > 0xFFFFFFFFu) {
            value = 0xFFFFFFFFu;
        }
        return make_token(Token::Type::Number, text_.substr(start, pos_ - start),
                          static_cast<uint32_t>(value));
    }

    std::string text_;
    std::size_t pos_ = 0;
    std::size_t line_ = 1;
    std::size_t column_ = 1;
};

struct ParseError : std::runtime_error {
    explicit ParseError(const std::string& msg) : std::runtime_error(msg) {}
};

class Parser {
  public:
    explicit Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

    bool parse(std::vector<Engine::Rule>& out_rules) {
        try {
            while (true) {
                skip_eol();
                const Token& tok = peek();
                if (tok.type == Token::Type::End) {
                    break;
                }
                Engine::Rule rule;
                parse_rule(rule);
                out_rules.push_back(rule);
                if (out_rules.size() >= MAX_RULES) {
                    std::cerr << "Filter warning: maximum rule count reached" << std::endl;
                    break;
                }
            }
        } catch (const ParseError& err) {
            std::cerr << "Filter parse error: " << err.what() << std::endl;
            return false;
        }
        return true;
    }

  private:
    struct RuleCounters {
        uint32_t inbound = 0;
        uint32_t outbound = 0;
    } counters_;

    void parse_rule(Engine::Rule& rule) {
        parse_action(rule);
        parse_direction(rule);
        if (rule.dir_mask == DIR_IN_MASK) {
            rule.index = ++counters_.inbound;
        } else {
            rule.index = ++counters_.outbound;
        }

        while (true) {
            const Token& tok = peek();
            if (tok.type == Token::Type::End || tok.type == Token::Type::EndOfLine) {
                break;
            }
            if (tok.type != Token::Type::Identifier) {
                throw error(tok, "unexpected token '" + tok.text + "'");
            }
            parse_clause(rule);
        }
        consume_eol();
        rule.requires_l4 = rule.src_requires_l4 || rule.dst_requires_l4;
    }

    void parse_action(Engine::Rule& rule) {
        const Token& tok = expect(Token::Type::Identifier, "expected action token");
        std::string word = to_lower(tok.text);
        if (word == "block") {
            rule.actions = ActionFlag::Block;
        } else if (word == "pass") {
            rule.actions = ActionFlag::Pass;
        } else if (word == "dnat") {
            rule.actions = ActionFlag::Dnat;
        } else if (word == "shape") {
            rule.actions = ActionFlag::Shape;
            const Token& rate_tok = expect(Token::Type::Identifier, "expected 'rate'");
            if (to_lower(rate_tok.text) != "rate") {
                throw error(rate_tok, "expected 'rate' after 'shape'");
            }
            const Token& value = expect(Token::Type::Number, "expected rate value");
            rule.shape_rate = static_cast<int>(value.number);
        } else {
            throw error(tok, "unknown action '" + tok.text + "'");
        }
    }

    void parse_direction(Engine::Rule& rule) {
        const Token& tok = expect(Token::Type::Identifier, "expected direction token");
        std::string word = to_lower(tok.text);
        if (word == "in") {
            rule.dir_mask = DIR_IN_MASK;
        } else if (word == "out") {
            rule.dir_mask = DIR_OUT_MASK;
        } else if (word == "any") {
            rule.dir_mask = DIR_IN_MASK | DIR_OUT_MASK;
        } else {
            throw error(tok, "expected 'in' or 'out'");
        }
    }

    void parse_clause(Engine::Rule& rule) {
        const Token& tok = expect(Token::Type::Identifier, "unexpected token");
        std::string keyword = to_lower(tok.text);
        if (keyword == "proto") {
            parse_proto(rule);
            return;
        }
        if (keyword == "from") {
            parse_target(rule, rule.src_ip, rule.src_ports, rule.src_requires_l4);
            return;
        }
        if (keyword == "to") {
            parse_target(rule, rule.dst_ip, rule.dst_ports, rule.dst_requires_l4);
            return;
        }
        if (keyword == "flags") {
            parse_flags(rule);
            return;
        }
        if (keyword == "redir") {
            parse_redir(rule);
            return;
        }
        if (keyword == "rate") {
            parse_rate(rule, tok);
            return;
        }
        throw error(tok, "unexpected clause '" + tok.text + "'");
    }

    void parse_proto(Engine::Rule& rule) {
        const Token& tok = expect_any({Token::Type::Number, Token::Type::Identifier},
                                      "expected protocol value");
        if (tok.type == Token::Type::Number) {
            if (tok.number > 255) {
                throw error(tok, "protocol number out of range");
            }
            rule.proto = static_cast<uint8_t>(tok.number);
        } else {
            std::string name = to_lower(tok.text);
            if (name == "ip" || name == "any") {
                rule.proto.reset();
                return;
            }
            protoent* pe = getprotobyname(tok.text.c_str());
            if (!pe) {
                throw error(tok, "unknown protocol '" + tok.text + "'");
            }
            rule.proto = static_cast<uint8_t>(pe->p_proto);
        }
    }

    void parse_target(Engine::Rule& rule, Engine::IpCondition& ip_cond,
                      Engine::PortCondition& port_cond, bool& requires_l4) {
        bool have_network = false;
        bool have_port = false;

        const Token& look = peek();
        if (look.type == Token::Type::Identifier && to_lower(look.text) != "port") {
            have_network = parse_network(ip_cond);
        }

        if (peek().type == Token::Type::Identifier && to_lower(peek().text) == "port") {
            have_port = parse_port(port_cond);
        }

        if (have_port) {
            requires_l4 = port_cond.is_active();
        }

        if (!have_network && !have_port) {
            ip_cond.any = true;
        }
    }

    bool parse_network(Engine::IpCondition& ip_cond) {
        const Token& host_tok = expect(Token::Type::Identifier, "expected address");
        uint32_t ip = 0;
        bool has_ip = parse_ipv4(host_tok.text, ip);
        if (has_ip) {
            ip_cond.any = false;
            ip_cond.mask = 0xFFFFFFFFu;
            ip_cond.network = ip;
        }

        if (peek().type == Token::Type::Identifier && to_lower(peek().text) == "mask") {
            advance();
            const Token& mask_tok = expect(Token::Type::Identifier, "expected mask value");
            uint32_t mask_ip = 0;
            if (!parse_ipv4(mask_tok.text, mask_ip)) {
                throw error(mask_tok, "invalid mask");
            }
            ip_cond.any = false;
            ip_cond.mask = mask_ip;
            ip_cond.network = ip & mask_ip;
            return true;
        }
        if (peek().type == Token::Type::Slash) {
            advance();
            const Token& prefix_tok = expect(Token::Type::Number, "expected prefix length");
            if (prefix_tok.number > 32) {
                throw error(prefix_tok, "CIDR prefix out of range");
            }
            uint32_t mask = prefix_to_mask(static_cast<int>(prefix_tok.number));
            ip_cond.any = false;
            ip_cond.mask = mask;
            ip_cond.network = ip & mask;
            return true;
        }

        return has_ip;
    }

    bool parse_port(Engine::PortCondition& port_cond) {
        expect(Token::Type::Identifier, "expected 'port'");
        if (peek().type == Token::Type::Number) {
            Token lo = advance();
            if (peek().type == Token::Type::Colon) {
                advance();
                const Token& hi = expect(Token::Type::Number, "expected upper bound");
                if (lo.number > hi.number) {
                    throw error(lo, "invalid port range");
                }
                port_cond.type = Engine::PortCondition::Type::Range;
                port_cond.range_lo = static_cast<uint16_t>(lo.number);
                port_cond.range_hi = static_cast<uint16_t>(hi.number);
                return true;
            }
            port_cond.type = Engine::PortCondition::Type::Eq;
            port_cond.values.clear();
            port_cond.values.push_back(static_cast<uint16_t>(lo.number));
            return true;
        }

        const Token& cmp = expect(Token::Type::Identifier, "expected comparator");
        std::string word = to_lower(cmp.text);
        if (word == "eq" || word == "ne") {
            parse_port_list(port_cond, word == "eq");
            return true;
        }
        if (word == "lt" || word == "le" || word == "gt" || word == "ge") {
            const Token& value = expect(Token::Type::Number, "expected port value");
            port_cond.values.clear();
            port_cond.threshold = static_cast<uint16_t>(value.number);
            if (word == "lt") {
                port_cond.type = Engine::PortCondition::Type::Lt;
            } else if (word == "le") {
                port_cond.type = Engine::PortCondition::Type::Le;
            } else if (word == "gt") {
                port_cond.type = Engine::PortCondition::Type::Gt;
            } else {
                port_cond.type = Engine::PortCondition::Type::Ge;
            }
            return true;
        }

        throw error(cmp, "unknown port comparator '" + cmp.text + "'");
    }

    void parse_port_list(Engine::PortCondition& port_cond, bool equality) {
        port_cond.type = equality ? Engine::PortCondition::Type::Eq
                                  : Engine::PortCondition::Type::Ne;
        port_cond.values.clear();
        const Token& first = expect(Token::Type::Number, "expected port value");
        port_cond.values.push_back(static_cast<uint16_t>(first.number));
        while (peek().type == Token::Type::Comma) {
            advance();
            const Token& value = expect(Token::Type::Number, "expected port value");
            if (port_cond.values.size() < MAX_PORTS) {
                port_cond.values.push_back(static_cast<uint16_t>(value.number));
            }
        }
    }

    void parse_flags(Engine::Rule& rule) {
        const Token& set_tok = expect(Token::Type::Identifier, "expected flag set");
        uint8_t set_bits = parse_flag_string(set_tok);
        uint8_t mask_bits = set_bits;
        if (!rule.proto) {
            rule.proto = IPPROTO_TCP;
        }
        if (peek().type == Token::Type::Slash) {
            advance();
            const Token& mask_tok = expect(Token::Type::Identifier, "expected flag mask");
            mask_bits = parse_flag_string(mask_tok);
        }
        rule.flags_set = set_bits;
        rule.flags_mask = mask_bits;
    }

    uint8_t parse_flag_string(const Token& tok) {
        uint8_t bits = 0;
        for (char raw : tok.text) {
            char ch = static_cast<char>(std::toupper(static_cast<unsigned char>(raw)));
            switch (ch) {
            case 'F': bits |= 0x01; break;
            case 'S': bits |= 0x02; break;
            case 'R': bits |= 0x04; break;
            case 'P': bits |= 0x08; break;
            case 'A': bits |= 0x10; break;
            case 'U': bits |= 0x20; break;
            default:
                throw error(tok, "invalid TCP flag character");
            }
        }
        if (bits == 0) {
            throw error(tok, "empty TCP flag specification");
        }
        return bits;
    }

    void parse_redir(Engine::Rule& rule) {
        const Token& to_tok = expect(Token::Type::Identifier, "expected 'to'");
        if (to_lower(to_tok.text) != "to") {
            throw error(to_tok, "expected 'to'");
        }
        const Token& host_tok = expect(Token::Type::Identifier, "expected redirect host");
        uint32_t ip = 0;
        if (!parse_ipv4(host_tok.text, ip)) {
            throw error(host_tok, "invalid redirect IP");
        }
        const Token& port_tok = expect(Token::Type::Identifier, "expected 'port'");
        if (to_lower(port_tok.text) != "port") {
            throw error(port_tok, "expected 'port'");
        }
        const Token& value = expect(Token::Type::Number, "expected redirect port");
        rule.dnat.ip = ip;
        rule.dnat.port = static_cast<uint16_t>(value.number);
        rule.dnat.valid = true;
        rule.actions |= ActionFlag::Dnat;
    }

    void parse_rate(Engine::Rule& rule, const Token& keyword) {
        const Token& value = expect(Token::Type::Number, "expected rate value");
        rule.actions |= ActionFlag::Shape;
        rule.shape_rate = static_cast<int>(value.number);
    }

    void skip_eol() {
        while (peek().type == Token::Type::EndOfLine) {
            advance();
        }
    }

    void consume_eol() {
        if (peek().type == Token::Type::EndOfLine) {
            advance();
        }
    }

    const Token& peek() const { return tokens_[pos_]; }

    const Token& advance() {
        if (pos_ < tokens_.size() - 1) {
            ++pos_;
        }
        return tokens_[pos_];
    }

    const Token& expect(Token::Type type, const char* message) {
        const Token& tok = peek();
        if (tok.type != type) {
            throw error(tok, message);
        }
        advance();
        return tok;
    }

    const Token& expect_any(std::initializer_list<Token::Type> types, const char* message) {
        const Token& tok = peek();
        for (auto type : types) {
            if (tok.type == type) {
                advance();
                return tok;
            }
        }
        throw error(tok, message);
    }

    ParseError error(const Token& tok, const std::string& message) const {
        std::ostringstream oss;
        oss << "line " << tok.line << ": " << message;
        return ParseError(oss.str());
    }

    std::vector<Token> tokens_;
    std::size_t pos_ = 0;
};

} // namespace

bool Engine::PortCondition::matches(uint16_t port) const {
    switch (type) {
    case Type::Any:
        return true;
    case Type::Eq:
        return !values.empty() && std::find(values.begin(), values.end(), port) != values.end();
    case Type::Ne:
        return std::find(values.begin(), values.end(), port) == values.end();
    case Type::Lt:
        return port < threshold;
    case Type::Le:
        return port <= threshold;
    case Type::Gt:
        return port > threshold;
    case Type::Ge:
        return port >= threshold;
    case Type::Range:
        if (range_lo == 0 && range_hi == 0) {
            return true;
        }
        return port >= range_lo && port <= range_hi;
    }
    return true;
}

bool Engine::PortCondition::is_active() const {
    if (type == Type::Any) {
        return false;
    }
    if ((type == Type::Eq || type == Type::Ne) && values.empty()) {
        return false;
    }
    return true;
}

Engine::Engine() {
    if (const char* env = std::getenv("SWEETSPOT_FILTER_PATH")) {
        set_config_path(env);
    }
}

Engine& Engine::instance() {
    static Engine engine;
    return engine;
}

std::string Engine::derive_name_from_path(const std::filesystem::path& path) {
    auto stem = path.stem().string();
    if (!stem.empty()) {
        return stem;
    }
    return path.filename().string();
}

void Engine::set_config_path(const std::string& path) {
    std::filesystem::path p(path);
    auto name = derive_name_from_path(p);
    LOG(DEBUG_FILTER, "filter set_config_path updating name=", name, " path=", p.string());
    load_filter(name, p);
    std::lock_guard<std::mutex> guard(mutex_);
    default_filter_ = name;
    default_path_ = p;
}

void Engine::load_filter(const std::string& name, const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        std::cerr << "Filter warning: file '" << path << "' not found" << std::endl;
        return;
    }
    LOG(DEBUG_FILTER, "filter load begin name=", name, " path=", path.string());
    std::vector<Rule> rules = parse_file(path);
    if (rules.empty()) {
        std::cerr << "Filter warning: no rules loaded from '" << path << "'" << std::endl;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    filters_[name] = FilterSet{std::move(rules), path};
    if (default_filter_.empty()) {
        default_filter_ = name;
        default_path_ = path;
    }
    LOG(DEBUG_FILTER, "filter load complete name=", name, " rules=", filters_[name].rules.size(),
        " path=", path.string());
}

void Engine::load_directory(const std::filesystem::path& dir, bool recursive) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        std::cerr << "Filter warning: directory '" << dir << "' not found" << std::endl;
        return;
    }
    LOG(DEBUG_FILTER, "filter load_directory path=", dir, " recursive=", recursive);
    std::size_t loaded = 0;
    if (recursive) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            load_filter(derive_name_from_path(entry.path()), entry.path());
            ++loaded;
        }
    } else {
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            load_filter(derive_name_from_path(entry.path()), entry.path());
            ++loaded;
        }
    }
    LOG(DEBUG_FILTER, "filter load_directory complete path=", dir, " loaded=", loaded);
}

void Engine::reload() {
    std::vector<std::pair<std::string, std::filesystem::path>> to_reload;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (const auto& [name, set] : filters_) {
            if (!set.source.empty()) {
                to_reload.emplace_back(name, set.source);
            }
        }
        if (to_reload.empty() && !default_path_.empty()) {
            to_reload.emplace_back(default_filter_, default_path_);
        }
    }
    LOG(DEBUG_FILTER, "filter reload targets=", to_reload.size());
    for (const auto& [name, path] : to_reload) {
        LOG(DEBUG_FILTER, "filter reload name=", name, " path=", path.string());
        load_filter(name, path);
    }
}

Decision Engine::evaluate(const PacketState& state) const {
    std::string filter_name;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        filter_name = default_filter_;
    }
    return evaluate(state, filter_name);
}

Decision Engine::evaluate(const PacketState& state, const std::string& filter_name) const {
    if (filter_name.empty()) {
        return Decision{};
    }
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = filters_.find(filter_name);
    if (it == filters_.end()) {
        LOG(DEBUG_FILTER, "filter evaluate missing name=", filter_name);
        return Decision{};
    }
    LOG(DEBUG_FILTER, "filter evaluate name=", filter_name,
        " state=", describe_packet_state(state), " rules=", it->second.rules.size());
    auto decision = evaluate_rules(state, filter_name, it->second.rules);
    LOG(DEBUG_FILTER, "filter decision name=", filter_name, " allow=", decision.allow,
        " matched=", decision.matched, " rule=", decision.rule_index);
    return decision;
}

std::size_t Engine::rule_count() const {
    std::lock_guard<std::mutex> guard(mutex_);
    if (default_filter_.empty()) {
        return 0;
    }
    auto it = filters_.find(default_filter_);
    return it != filters_.end() ? it->second.rules.size() : 0;
}

std::size_t Engine::rule_count(const std::string& filter_name) const {
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = filters_.find(filter_name);
    return it != filters_.end() ? it->second.rules.size() : 0;
}

std::vector<std::string> Engine::list_filters() const {
    std::vector<std::string> names;
    std::lock_guard<std::mutex> guard(mutex_);
    names.reserve(filters_.size());
    for (const auto& [name, _] : filters_) {
        names.push_back(name);
    }
    return names;
}

std::string Engine::default_filter_name() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return default_filter_;
}

Decision Engine::evaluate_rules(const PacketState& state, const std::string& filter_name,
                                const std::vector<Rule>& rules) const {
    Decision decision;
    decision.allow = true;
    for (const Rule& rule : rules) {
        if ((rule.dir_mask & direction_to_mask(state.direction)) == 0) {
            continue;
        }
        if (!state.has_ipv4) {
            break;
        }
        if (rule.proto) {
            if (*rule.proto != state.protocol) {
                continue;
            }
        }
        if (!rule.src_ip.any) {
            if ((state.src_ip & rule.src_ip.mask) != rule.src_ip.network) {
                continue;
            }
        }
        if (!rule.dst_ip.any) {
            if ((state.dst_ip & rule.dst_ip.mask) != rule.dst_ip.network) {
                continue;
            }
        }
        if (rule.requires_l4 && !state.has_l4) {
            continue;
        }
        if (rule.src_requires_l4 && !rule.src_ports.matches(state.src_port)) {
            continue;
        }
        if (rule.dst_requires_l4 && !rule.dst_ports.matches(state.dst_port)) {
            continue;
        }
        if (rule.flags_mask) {
            if (!state.tcp_flags_valid) {
                continue;
            }
            if ((state.tcp_flags & rule.flags_mask) != rule.flags_set) {
                continue;
            }
        }

        decision.matched = true;
        decision.rule_index = rule.index;
        decision.actions = rule.actions;
        decision.shape_rate = rule.shape_rate;
        decision.dnat = rule.dnat;
        decision.allow = !has_flag(rule.actions, ActionFlag::Block);
        LOG(DEBUG_FILTER, "filter rule matched name=", filter_name, " index=", rule.index,
            " allow=", decision.allow, " actions=", static_cast<int>(decision.actions),
            " shape=", decision.shape_rate);
        if (!decision.allow) {
            return decision;
        }
        return decision;
    }
    LOG(DEBUG_FILTER, "filter no match name=", filter_name, " allow=true");
    return decision;
}

std::vector<Engine::Rule> Engine::parse_file(const std::filesystem::path& path) const {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Filter warning: unable to open '" << path << "'" << std::endl;
        return {};
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    if (content.empty()) {
        return {};
    }
    Tokenizer tokenizer(content);
    auto tokens = tokenizer.run();
    LOG(DEBUG_FILTER, "filter parse tokens path=", path.string(), " count=", tokens.size());
    Parser parser(std::move(tokens));
    std::vector<Rule> rules;
    if (!parser.parse(rules)) {
        LOG(DEBUG_FILTER, "filter parse failed path=", path.string());
        return {};
    }
    LOG(DEBUG_FILTER, "filter parse success path=", path.string(), " rules=", rules.size());
    return rules;
}

} // namespace filters
