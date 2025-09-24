#pragma once
#include <cstdint>
#include <tuple>
#include <cstring>
#include <algorithm>

namespace CPUFanoutHash {

// ==============================
// SipHash key
// ==============================
struct SipKey {
    uint64_t k0;
    uint64_t k1;
};

// Глобальный ключ (заполни через set_siphash_key* реальным hashrnd)
inline SipKey& siphash_key() {
    static SipKey key{0, 0};
    return key;
}
inline void set_siphash_key(uint64_t k0, uint64_t k1) {
    siphash_key().k0 = k0;
    siphash_key().k1 = k1;
}
inline void set_siphash_key_bytes(const unsigned char key16[16]) {
    uint64_t k0 = 0, k1 = 0;
    std::memcpy(&k0, key16 + 0, 8);
    std::memcpy(&k1, key16 + 8, 8);
    set_siphash_key(k0, k1);
}

// ==============================
// LE helpers (как get_unaligned_le* в ядре)
// ==============================
static inline uint16_t get_unaligned_le16(const void* p) {
    const unsigned char* b = static_cast<const unsigned char*>(p);
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}
static inline uint32_t get_unaligned_le32(const void* p) {
    const unsigned char* b = static_cast<const unsigned char*>(p);
    return  (uint32_t)b[0]
          | ((uint32_t)b[1] << 8)
          | ((uint32_t)b[2] << 16)
          | ((uint32_t)b[3] << 24);
}
static inline uint64_t get_unaligned_le64(const void* p) {
    const unsigned char* b = static_cast<const unsigned char*>(p);
    return  (uint64_t)b[0]
          | ((uint64_t)b[1] << 8)
          | ((uint64_t)b[2] << 16)
          | ((uint64_t)b[3] << 24)
          | ((uint64_t)b[4] << 32)
          | ((uint64_t)b[5] << 40)
          | ((uint64_t)b[6] << 48)
          | ((uint64_t)b[7] << 56);
}

// ==============================
// SipHash-2-4 — «как в ядре» (__siphash_unaligned)
// ==============================
static inline uint64_t ROTL64(uint64_t x, unsigned r) {
    return (x << r) | (x >> (64 - r));
}
#define SIPROUND(v0,v1,v2,v3) do {            \
    v0 += v1; v1 = ROTL64(v1,13); v1 ^= v0;   \
    v0 = ROTL64(v0,32);                       \
    v2 += v3; v3 = ROTL64(v3,16); v3 ^= v2;   \
    v0 += v3; v3 = ROTL64(v3,21); v3 ^= v0;   \
    v2 += v1; v1 = ROTL64(v1,17); v1 ^= v2;   \
    v2 = ROTL64(v2,32);                       \
} while(0)

inline uint64_t siphash24_kernel_compat(const void* data_void, size_t len, const SipKey& k)
{
    const unsigned char* data = static_cast<const unsigned char*>(data_void);
    const unsigned char* end  = data + (len - (len % sizeof(uint64_t)));
    const unsigned char left  = (unsigned char)(len & (sizeof(uint64_t) - 1));

    // PREAMBLE как в lib/siphash.c
    uint64_t v0 = 0x736f6d6570736575ULL; // SIPHASH_CONST_0
    uint64_t v1 = 0x646f72616e646f6dULL; // SIPHASH_CONST_1
    uint64_t v2 = 0x6c7967656e657261ULL; // SIPHASH_CONST_2
    uint64_t v3 = 0x7465646279746573ULL; // SIPHASH_CONST_3
    uint64_t b  = ((uint64_t)len) << 56;

    v3 ^= k.k1;
    v2 ^= k.k0;
    v1 ^= k.k1;
    v0 ^= k.k0;

    // основной цикл по 8 байт (LE, unaligned)
    for (const unsigned char* p = data; p != end; p += 8) {
        uint64_t m = get_unaligned_le64(p);
        v3 ^= m; SIPROUND(v0,v1,v2,v3); SIPROUND(v0,v1,v2,v3); v0 ^= m;
    }

    // хвост: точь-в-точь как в __siphash_unaligned (ветка без DCACHE_WORD_ACCESS)
    switch (left) {
    case 7: b |= ((uint64_t)end[6]) << 48; [[fallthrough]];
    case 6: b |= ((uint64_t)end[5]) << 40; [[fallthrough]];
    case 5: b |= ((uint64_t)end[4]) << 32; [[fallthrough]];
    case 4: b |= get_unaligned_le32(end); break;
    case 3: b |= ((uint64_t)end[2]) << 16; [[fallthrough]];
    case 2: b |= get_unaligned_le16(end); break;
    case 1: b |= end[0]; break;
    case 0: break;
    }

    // POSTAMBLE
    v3 ^= b; SIPROUND(v0,v1,v2,v3); SIPROUND(v0,v1,v2,v3); v0 ^= b;
    v2 ^= 0xff;
    SIPROUND(v0,v1,v2,v3); SIPROUND(v0,v1,v2,v3);
    SIPROUND(v0,v1,v2,v3); SIPROUND(v0,v1,v2,v3);
    return (v0 ^ v1) ^ (v2 ^ v3);
}

#undef SIPROUND

// ==============================
// Выбор слота (bucket)
// ==============================
inline uint32_t select_cpu(uint32_t hash, uint32_t num) {
    return num ? (hash % num) : 0;
    // или fastmod: (uint32_t)(((__uint128_t)hash * num) >> 64)
}

// ==============================
// Симметризация (как __flow_hash_consistentify)
// ==============================
inline void consistentify_v4(uint32_t& saddr_be, uint32_t& daddr_be,
                             uint16_t& sport_be, uint16_t& dport_be)
{
    bool need_swap = false;
    if (daddr_be < saddr_be) need_swap = true;
    else if (daddr_be == saddr_be && dport_be < sport_be) need_swap = true;

    if (need_swap) {
        std::swap(saddr_be, daddr_be);
        std::swap(sport_be, dport_be);
    }
}

// ==============================
// Хэш IPv4 (u32) — строим ровно те 12 байт, что ждёт ядро в TCP/UDP,
// и считаем siphash «как в ядре». 0 -> 1.
// ВАЖНО: для ICMP и части нестандартных случаев ядро хэширует другой набор
// (обычно только адреса). Этот код — для TCP/UDP 4-tuple.
// ==============================
inline uint32_t hash_ipv4(uint32_t saddr_be, uint32_t daddr_be,
                          uint16_t sport_be, uint16_t dport_be, uint8_t proto = 0)
{
    // Для честного сравнения с ядром по TCP/UDP — симметризуем и считаем 12 байт.
    consistentify_v4(saddr_be, daddr_be, sport_be, dport_be);

    unsigned char buf[12];
    uint32_t ports_be = (uint32_t(sport_be) << 16) | dport_be;
    std::memcpy(buf + 0, &saddr_be, 4);
    std::memcpy(buf + 4, &daddr_be, 4);
    std::memcpy(buf + 8, &ports_be, 4);

    uint64_t h64 = siphash24_kernel_compat(buf, sizeof(buf), siphash_key());
    uint32_t h32 = (uint32_t)h64;
    return h32 ? h32 : 1;
}

inline uint32_t hash_udp(uint32_t saddr_be, uint32_t daddr_be,
                         uint16_t sport_be, uint16_t dport_be)
{
    return hash_ipv4(saddr_be, daddr_be, sport_be, dport_be, 17);
}

// tuple = (saddr_be, daddr_be, sport_be, dport_be, proto)
inline uint32_t hash_tuple(const std::tuple<uint32_t,uint32_t,uint16_t,uint16_t,uint8_t>& t) {
    uint32_t saddr_be, daddr_be; uint16_t sport_be, dport_be; uint8_t proto;
    std::tie(saddr_be, daddr_be, sport_be, dport_be, proto) = t;
    return hash_ipv4(saddr_be, daddr_be, sport_be, dport_be, proto);
}

} // namespace CPUFanoutHash

