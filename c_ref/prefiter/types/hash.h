#ifndef PREFILTER_HASH_H
#define PREFILTER_HASH_H

#include <stddef.h>
#include <stdint.h>

uint64_t hash_fnv1a64(const uint8_t *bytes, size_t len);

#endif
