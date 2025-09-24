#include <iostream>
#include <fstream>
#include <sstream>
#include <tuple>
#include <string>
#include <vector>
#include <arpa/inet.h>

#include "../common/jenkins_hash.hpp"   // твоя реализация CPUFanoutHash::hash_ipv4()

// Структура строки из CSV
struct Record {
    uint32_t saddr_be;
    uint32_t daddr_be;
    uint16_t sport_be;
    uint16_t dport_be;
    uint8_t  proto;
    uint32_t kernel_hash;
};

// Парсер CSV из /tmp/flowhash.csv
std::vector<Record> load_csv(const std::string &fname) {
    std::ifstream f(fname);
    std::vector<Record> rows;
    std::string line;

    // первая строка — заголовок, пропускаем
    std::getline(f, line);

    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);

        Record r{};
        std::string token;

        std::getline(ss, token, ','); r.saddr_be = std::stoul(token);
        std::getline(ss, token, ','); r.daddr_be = std::stoul(token);
        std::getline(ss, token, ','); r.sport_be = std::stoul(token);
        std::getline(ss, token, ','); r.dport_be = std::stoul(token);
        std::getline(ss, token, ','); r.proto    = std::stoul(token);
        std::getline(ss, token, ','); r.kernel_hash = std::stoul(token);

        rows.push_back(r);
    }
    return rows;
}

int main() {
    auto data = load_csv("/tmp/flowhash.csv");
    if (data.empty()) {
        std::cerr << "No data in CSV\n";
        return 1;
    }

    int mismatches = 0;
   // CPUFanoutHash::set_siphash_key(
   // 0xd69eae9d978c9e16ULL,
   // 0xc9a5c97d4404f229ULL
//);

    for (auto &r : data) {
        // считаем userspace-хэш

        uint32_t user_hash = CPUFanoutHash::hash_ipv4(
            r.saddr_be, r.daddr_be, r.sport_be, r.dport_be, r.proto
        );

        if (user_hash != r.kernel_hash) {
            mismatches++;
            struct in_addr sa{r.saddr_be}, da{r.daddr_be};
            std::cout << "❌ MISMATCH "
                      << inet_ntoa(sa) << ":" << ntohs(r.sport_be)
                      << " -> " << inet_ntoa(da) << ":" << ntohs(r.dport_be)
                      << " proto=" << int(r.proto)
                      << " kernel=0x" << std::hex << r.kernel_hash
                      << " user=0x" << user_hash
                      << std::dec << "\n";
        }
    }

    if (mismatches == 0)
        std::cout << "✅ All hashes match!\n";
    else
        std::cout << "Mismatches: " << mismatches << "\n";

    return 0;
}

