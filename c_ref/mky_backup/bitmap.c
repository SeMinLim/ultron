#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "singleton.h"
#include "bitmap.h"


void bitmap_clear(Bitmap *b)
{
    memset(b->data, 0, BITMAP_BYTES + BITMAP_GUARD);
}

void bitmap_set_gram(Bitmap *b, const uint8_t *gram)
{
    bitmap_set(b, bitmap_idx(gram));
}

bool bitmap_test_gram(const Bitmap *b, const uint8_t *gram)
{
    return bitmap_get(b, bitmap_idx(gram));
}

bool verify_ms_bitmap(Bitmap *b_arr, Bitmap *v_arr, SingletonResult *sr) {
    bool res = true;

    Bitmap* base_bm = b_arr;
    for (int i = 0; i < sr->count; i++) {
        uint8_t* gram = sr->assigns[i].gram;
        int stage = sr->assigns[i].stage;
        uint8_t* next_grams = sr->assigns[i].next_grams;

        // Checking base singleton bitmap.
        if (!bitmap_test_gram(base_bm, gram)) {
            res = false;
            break;
        }

        // Checking verifying & next stage.
        for (int cur_stage=0; cur_stage < stage-1; cur_stage++) {
            Bitmap* curr_v_bm = v_arr + cur_stage;
            if(!bitmap_test_gram(curr_v_bm, gram)) {
                res = false;
                break;
            }

            uint8_t* next_gram = malloc((size_t) (sizeof(uint8_t) * 3));
            memcpy(
                next_gram, 
                next_grams + (cur_stage * 3), 
                (size_t) (sizeof(uint8_t) * 3)
            );
            Bitmap* curr_bm = b_arr + (cur_stage + 1);
            if(!bitmap_test_gram(curr_bm, next_gram)) {
                res = false;
                break;
            }
        }
    }

    return res;
}
