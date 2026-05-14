// ref: https://github.com/FastFilter/xor_singleheader
// ref: https://doi.org/10.1145/3376122 (Xor Filters, Graf & Lemire, JEA 2020)

#ifndef XOR_FILTER_H
#define XOR_FILTER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    uint64_t seed;
    uint32_t block_len;
    uint8_t *fp;
} XorFilter8;

uint64_t xor_murmur64(uint64_t h);

bool xor8_build(XorFilter8 *f, uint64_t *keys, uint32_t n);
bool xor8_contain(const XorFilter8 *f, uint64_t key);
void xor8_free(XorFilter8 *f);

#endif
