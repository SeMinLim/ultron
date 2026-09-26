#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t *bits;
    size_t    n_bits;   /* always a multiple of 64 */
    int       k;        /* number of hash probes   */
    size_t    count;
} BloomFilter;

/* General: derive optimal m and k from target FPR and expected item count. */
BloomFilter *bloom_create(size_t n_items, double fpr);

BloomFilter *bloom_create_fixed(size_t m_bytes, int k);

void bloom_destroy(BloomFilter *f);

void bloom_add(BloomFilter *f, uint64_t key);
bool bloom_test(const BloomFilter *f, uint64_t key);

#endif
