#ifndef HASH_H
#define HASH_H

#include <stdint.h>

uint64_t xor_murmur64(uint64_t h);

/* Fibonacci hashing: multiply by floor(2^N / phi), shift down to desired bits.
 * Distributes keys uniformly even when inputs are sequential or aligned. */
static inline uint32_t fib_hash32(uint32_t key, int bits)
{
    return (key * UINT32_C(0x9e3779b9)) >> (32 - bits);
}

static inline uint64_t fib_hash64(uint64_t key, int bits)
{
    return (key * UINT64_C(0x9e3779b97f4a7c15)) >> (64 - bits);
}

#endif
