#include "siphash.h"
#include <string.h>

#define ROTL64(x, b) ((uint64_t)(((x) << (b)) | ((x) >> (64 - (b)))))

#define SIPROUND            \
    do {                    \
        v0 += v1;           \
        v1 = ROTL64(v1,13); \
        v1 ^= v0;           \
        v0 = ROTL64(v0,32); \
        v2 += v3;           \
        v3 = ROTL64(v3,16); \
        v3 ^= v2;           \
        v0 += v3;           \
        v3 = ROTL64(v3,21); \
        v3 ^= v0;           \
        v2 += v1;           \
        v1 = ROTL64(v1,17); \
        v1 ^= v2;           \
        v2 = ROTL64(v2,32); \
    } while (0)

uint64_t siphash(const void *data, size_t len, const siphash_key_t *key)
{
    const unsigned char *in = (const unsigned char *)data;
    const unsigned char *end = in + (len & ~7ULL);
    size_t left = len & 7;

    uint64_t v0 = 0x736f6d6570736575ULL ^ key->key[0];
    uint64_t v1 = 0x646f72616e646f6dULL ^ key->key[1];
    uint64_t v2 = 0x6c7967656e657261ULL ^ key->key[0];
    uint64_t v3 = 0x7465646279746573ULL ^ key->key[1];

    while (in != end) {
        uint64_t m = 0;
        memcpy(&m, in, 8);
        in += 8;
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }

    uint64_t b = ((uint64_t)len) << 56;
    switch (left) {
    case 7: b |= ((uint64_t)in[6]) << 48; [[fallthrough]];
    case 6: b |= ((uint64_t)in[5]) << 40; [[fallthrough]];
    case 5: b |= ((uint64_t)in[4]) << 32; [[fallthrough]];
    case 4: b |= ((uint64_t)in[3]) << 24; [[fallthrough]];
    case 3: b |= ((uint64_t)in[2]) << 16; [[fallthrough]];
    case 2: b |= ((uint64_t)in[1]) <<  8; [[fallthrough]];
    case 1: b |= ((uint64_t)in[0]); break;
    }

    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;

    return (v0 ^ v1) ^ (v2 ^ v3);
}

