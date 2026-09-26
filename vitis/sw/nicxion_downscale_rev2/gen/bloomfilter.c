#include <math.h>
#include <stdlib.h>
#include "bloomfilter.h"
#include "hash.h"

/* Kirsch-Mitzenmacher double-hashing: two independent hashes derive k positions.
 * position_i = (h1 + i*h2) mod n_bits.
 * h2 is forced odd so it stays coprime with power-of-2 n_bits. */
static void probe_positions(uint64_t key, size_t n_bits, int k, size_t *out)
{
    uint64_t a = xor_murmur64(key);
    uint64_t b = xor_murmur64(key ^ UINT64_C(0x9e3779b97f4a7c15));
    uint32_t h1 = (uint32_t)a;
    uint32_t h2 = ((uint32_t)(b >> 32)) | 1u;
    for (int i = 0; i < k; i++)
        out[i] = (size_t)((h1 + (uint32_t)i * h2) % (uint32_t)n_bits);
}

static BloomFilter *bloom_alloc(size_t n_bits, int k)
{
    BloomFilter *f = malloc(sizeof(BloomFilter));
    f->bits   = calloc(n_bits / 64, sizeof(uint64_t));
    f->n_bits = n_bits;
    f->k      = k;
    f->count  = 0;
    return f;
}

/* General: optimal m = -n*ln(p)/ln(2)^2, optimal k = (m/n)*ln(2). */
BloomFilter *bloom_create(size_t n_items, double fpr)
{
    if (n_items == 0 || fpr <= 0.0 || fpr >= 1.0)
        return NULL;

    double ln2  = 0.6931471805599453;
    double m    = -(double)n_items * log(fpr) / (ln2 * ln2);
    size_t n_bits = (size_t)m;
    if (n_bits < 64) n_bits = 64;
    n_bits = (n_bits + 63u) & ~(size_t)63u;

    int k = (int)((double)n_bits / (double)n_items * ln2 + 0.5);
    if (k < 1)  k = 1;
    if (k > 32) k = 32;

    return bloom_alloc(n_bits, k);
}

BloomFilter *bloom_create_fixed(size_t m_bytes, int k)
{
    if (m_bytes == 0 || (m_bytes & 7u) != 0 || k < 1 || k > 32)
        return NULL;

    size_t n_bits = m_bytes * 8u;
    n_bits = (n_bits + 63u) & ~(size_t)63u;

    return bloom_alloc(n_bits, k);
}

void bloom_destroy(BloomFilter *f)
{
    if (!f) return;
    free(f->bits);
    free(f);
}

void bloom_add(BloomFilter *f, uint64_t key)
{
    size_t pos[32];
    probe_positions(key, f->n_bits, f->k, pos);
    for (int i = 0; i < f->k; i++)
        f->bits[pos[i] / 64] |= UINT64_C(1) << (pos[i] % 64);
    f->count++;
}

bool bloom_test(const BloomFilter *f, uint64_t key)
{
    size_t pos[32];
    probe_positions(key, f->n_bits, f->k, pos);
    for (int i = 0; i < f->k; i++)
        if (!(f->bits[pos[i] / 64] & (UINT64_C(1) << (pos[i] % 64))))
            return false;
    return true;
}
