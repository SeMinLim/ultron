#include "hash.h"

uint64_t xor_murmur64(uint64_t h)
{
    h ^= h >> 33U;
    h *= UINT64_C(0xff51afd7ed558ccd);
    h ^= h >> 33U;
    h *= UINT64_C(0xc4ceb9fe1a85ec53);
    h ^= h >> 33U;
    return h;
}
