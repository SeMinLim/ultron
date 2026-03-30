// ref: https://github.com/FastFilter/xor_singleheader
// ref: https://doi.org/10.1145/3376122 (Xor Filters, Graf & Lemire, JEA 2020)

#include <stdlib.h>
#include <string.h>
#include "xor_filter.h"

#define XOR_MAX_TRIES 100

static inline uint64_t xor_murmur64(uint64_t h)
{
    h ^= h >> 33U;
    h *= UINT64_C(0xff51afd7ed558ccd);
    h ^= h >> 33U;
    h *= UINT64_C(0xc4ceb9fe1a85ec53);
    h ^= h >> 33U;
    return h;
}

static inline uint64_t xor_mix(uint64_t key, uint64_t seed)
{
    return xor_murmur64(key + seed);
}

static inline uint64_t xor_rotl64(uint64_t x, int r)
{
    return (x << r) | (x >> (64 - r));
}

static inline uint32_t xor_reduce(uint32_t x, uint32_t n)
{
    return (uint32_t)(((uint64_t)x * n) >> 32);
}

static inline uint8_t xor_fingerprint(uint64_t hash)
{
    return (uint8_t)(hash ^ (hash >> 32));
}

static inline void xor_h012_from_hash(uint64_t hash, uint32_t B,
                                       uint32_t *h0, uint32_t *h1, uint32_t *h2)
{
    *h0 = xor_reduce((uint32_t)hash,                  B);
    *h1 = xor_reduce((uint32_t)xor_rotl64(hash, 21), B) + B;
    *h2 = xor_reduce((uint32_t)xor_rotl64(hash, 42), B) + 2 * B;
}

static inline void xor_get_h012(uint64_t key, uint64_t seed, uint32_t B,
                                 uint32_t *h0, uint32_t *h1, uint32_t *h2)
{
    xor_h012_from_hash(xor_mix(key, seed), B, h0, h1, h2);
}

typedef struct { uint32_t count; uint64_t xor_key; } XorSlot;
typedef struct { uint64_t key;   uint32_t slot;    } XorEntry;

static int xor_cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint32_t xor_dedup(uint64_t *keys, uint32_t n)
{
    if (n == 0) return 0;
    qsort(keys, n, sizeof(uint64_t), xor_cmp_u64);
    uint32_t j = 1;
    for (uint32_t i = 1; i < n; i++)
        if (keys[i] != keys[i - 1]) keys[j++] = keys[i];
    return j;
}

bool xor8_build(XorFilter8 *f, uint64_t *keys, uint32_t n)
{
    if (n == 0) return false;

    n = xor_dedup(keys, n);

    uint32_t capacity = (uint32_t)(32 + 1.23 * (double)n);
    capacity = capacity / 3 * 3;
    uint32_t B = capacity / 3;
    uint32_t total = 3 * B;

    f->block_len  = B;
    f->fp         = calloc(total, sizeof(uint8_t));

    XorSlot  *slots = malloc(total * sizeof(XorSlot));
    XorEntry *stack = malloc(n    * sizeof(XorEntry));
    uint32_t *queue = malloc(total * sizeof(uint32_t));

    uint64_t seed = 0x726f656c6c616666ULL;
    bool ok = false;

    for (int attempt = 0; attempt < XOR_MAX_TRIES; attempt++) {
        seed = xor_murmur64(seed + attempt);
        f->seed = seed;

        memset(slots, 0, total * sizeof(XorSlot));

        for (uint32_t i = 0; i < n; i++) {
            uint32_t h0, h1, h2;
            xor_get_h012(keys[i], seed, B, &h0, &h1, &h2);
            slots[h0].count++; slots[h0].xor_key ^= keys[i];
            slots[h1].count++; slots[h1].xor_key ^= keys[i];
            slots[h2].count++; slots[h2].xor_key ^= keys[i];
        }

        uint32_t qhead = 0, qtail = 0;
        for (uint32_t i = 0; i < total; i++)
            if (slots[i].count == 1) queue[qtail++] = i;

        uint32_t stack_sz = 0;
        while (qhead < qtail) {
            uint32_t s = queue[qhead++];
            if (slots[s].count != 1) continue;

            uint64_t k = slots[s].xor_key;
            stack[stack_sz++] = (XorEntry){ k, s };

            uint32_t h0, h1, h2;
            xor_get_h012(k, seed, B, &h0, &h1, &h2);

            uint32_t others[2];
            int oi = 0;
            if (h0 != s) others[oi++] = h0;
            if (h1 != s) others[oi++] = h1;
            if (h2 != s) others[oi++] = h2;

            for (int j = 0; j < 2; j++) {
                slots[others[j]].count--;
                slots[others[j]].xor_key ^= k;
                if (slots[others[j]].count == 1)
                    queue[qtail++] = others[j];
            }
        }

        if (stack_sz == n) { ok = true; break; }
    }

    if (ok) {
        memset(f->fp, 0, total);
        for (int i = (int)n - 1; i >= 0; i--) {
            uint64_t k  = stack[i].key;
            uint32_t s  = stack[i].slot;
            uint32_t h0, h1, h2;
            xor_get_h012(k, f->seed, B, &h0, &h1, &h2);
            f->fp[s] = xor_fingerprint(xor_mix(k, f->seed))
                       ^ f->fp[h0] ^ f->fp[h1] ^ f->fp[h2];
        }
    } else {
        free(f->fp);
        f->fp = NULL;
    }

    free(slots);
    free(stack);
    free(queue);
    return ok;
}

bool xor8_contain(const XorFilter8 *f, uint64_t key)
{
    uint64_t hash = xor_mix(key, f->seed);
    uint8_t  fp   = xor_fingerprint(hash);
    uint32_t h0, h1, h2;
    xor_h012_from_hash(hash, f->block_len, &h0, &h1, &h2);
    return fp == (f->fp[h0] ^ f->fp[h1] ^ f->fp[h2]);
}

void xor8_free(XorFilter8 *f)
{
    free(f->fp);
    f->fp = NULL;
}
