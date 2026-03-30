#include <string.h>
#include "bitmap.h"

void bitmap_clear(Bitmap *b)
{
    memset(b->data, 0, BITMAP_BYTES);
}

void bitmap_set_gram(Bitmap *b, const uint8_t *gram)
{
    bitmap_set(b, bitmap_idx(gram));
}

bool bitmap_test_gram(const Bitmap *b, const uint8_t *gram)
{
    return bitmap_get(b, bitmap_idx(gram));
}
