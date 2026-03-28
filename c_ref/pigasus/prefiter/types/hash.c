#include "hash.h"

uint64_t hash_fnv1a64(const uint8_t *bytes, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}
