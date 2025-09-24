#include "flow_dissector.h"
#include "siphash.h"
#include <string.h>

void *flow_keys_hash_start(const struct flow_keys *flow)
{
    return (void *)&flow->addrs;
}

size_t flow_keys_hash_length(const struct flow_keys *flow)
{
    size_t diff = FLOW_KEYS_HASH_OFFSET + sizeof(flow->addrs);

    switch (flow->control.addr_type) {
    case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
        diff -= sizeof(flow->addrs.v4addrs);
        break;
    case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
        diff -= sizeof(flow->addrs.v6addrs);
        break;
    case FLOW_DISSECTOR_KEY_TIPC:
        diff -= sizeof(flow->addrs.tipckey);
        break;
    }
    return sizeof(*flow) - diff;
}

uint32_t __flow_hash_from_keys(const struct flow_keys *keys,
                               const siphash_key_t *keyval)
{
    uint32_t hash;

    hash = (uint32_t)siphash(flow_keys_hash_start(keys),
                             flow_keys_hash_length(keys),
                             keyval);
    if (!hash)
        hash = 1;
    return hash;
}

