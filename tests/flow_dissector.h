#pragma once
#include <stdint.h>
#include <netinet/in.h>
#include "siphash.h"

struct flow_dissector_key_control {
    uint16_t addr_type;
};

struct flow_dissector_key_basic {
    uint16_t n_proto;
    uint8_t  ip_proto;
    uint8_t  padding;
};

struct flow_dissector_key_addrs {
    union {
        struct {
            uint32_t src;
            uint32_t dst;
        } v4addrs;
        struct {
            struct in6_addr src;
            struct in6_addr dst;
        } v6addrs;
        struct {
            uint32_t key;
        } tipckey;
    };
};

struct flow_dissector_key_ports {
    uint16_t src;
    uint16_t dst;
};

struct flow_keys {
    struct flow_dissector_key_control control;
    struct flow_dissector_key_basic   basic;
    struct flow_dissector_key_addrs   addrs;
    struct flow_dissector_key_ports   ports;
};

// смещение
#define FLOW_KEYS_HASH_OFFSET offsetof(struct flow_keys, addrs)

// типы адресов
#define FLOW_DISSECTOR_KEY_IPV4_ADDRS 1
#define FLOW_DISSECTOR_KEY_IPV6_ADDRS 2
#define FLOW_DISSECTOR_KEY_TIPC       3

#ifdef __cplusplus
extern "C" {
#endif

void *flow_keys_hash_start(const struct flow_keys *flow);
size_t flow_keys_hash_length(const struct flow_keys *flow);

uint32_t __flow_hash_from_keys(const struct flow_keys *keys,
                               const siphash_key_t *keyval);

#ifdef __cplusplus
}
#endif

