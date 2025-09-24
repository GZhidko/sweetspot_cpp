#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t key[2];
} siphash_key_t;

#ifdef __cplusplus
extern "C" {
#endif

uint64_t siphash(const void *data, size_t len, const siphash_key_t *key);

#ifdef __cplusplus
}
#endif

