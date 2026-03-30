#ifndef BITMAP_H
#define BITMAP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define BITMAP_BITS  (1U << 24)
#define BITMAP_BYTES (BITMAP_BITS >> 3)
#define BITMAP_GUARD 3

typedef struct {
    uint8_t data[BITMAP_BYTES + BITMAP_GUARD];
} Bitmap;

static inline uint32_t bitmap_idx(const uint8_t *gram)
{
    return ((uint32_t)gram[0] << 16)
         | ((uint32_t)gram[1] <<  8)
         |  (uint32_t)gram[2];
}

static inline void bitmap_set(Bitmap *b, uint32_t idx)
{
    b->data[idx >> 3] |= (uint8_t)(1 << (idx & 7));
}

static inline bool bitmap_get(const Bitmap *b, uint32_t idx)
{
    return (b->data[idx >> 3] >> (idx & 7)) & 1;
}

void bitmap_clear(Bitmap *b);
void bitmap_set_gram(Bitmap *b, const uint8_t *gram);
bool bitmap_test_gram(const Bitmap *b, const uint8_t *gram);

#endif
