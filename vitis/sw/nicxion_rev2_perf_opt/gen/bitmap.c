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

int bitmap_count_bits(const Bitmap *b)
{
    int bits_set = 0;

    for (int i = 0; i < (int)BITMAP_BYTES; i++) {
        uint8_t byte = b->data[i];
        while (byte) {
            bits_set += byte & 1;
            byte >>= 1;
        }
    }

    return bits_set;
}

bool verify_ms_bitmap(Bitmap *b_arr, Bitmap *v_arr, SingletonResult *sr) {
    bool res = true;
    int n_fail_base = 0, n_fail_verif = 0, n_fail_next = 0;
    int first_fail_rid = -1, first_fail_stage = -1, first_fail_cur = -1;
    const char *first_fail_kind = NULL;

    // v_arr[k] (bit ②) is set by build only when every rule using this gram has
    // stage > k+1. Mirror that here so verify asserts the same invariant the
    // build (and the runtime matcher) operate on.
    uint8_t *min_stage_at_gram = malloc(BITMAP_BITS);
    memset(min_stage_at_gram, 0xff, BITMAP_BITS);
    for (int i = 0; i < sr->count; i++) {
        uint32_t gidx = bitmap_idx(sr->assigns[i].gram);
        int s = sr->assigns[i].stage;
        if (s < min_stage_at_gram[gidx])
            min_stage_at_gram[gidx] = (uint8_t)(s > 255 ? 255 : s);
    }

    Bitmap* base_bm = b_arr;
    for (int i = 0; i < sr->count; i++) {
        uint8_t* gram = sr->assigns[i].gram;
        int stage = sr->assigns[i].stage;
        uint8_t* next_grams = sr->assigns[i].next_grams;
        uint32_t gidx = bitmap_idx(gram);

        if (!bitmap_test_gram(base_bm, gram)) {
            res = false;
            n_fail_base++;
            if (first_fail_rid < 0) {
                first_fail_rid = sr->assigns[i].rule_id;
                first_fail_stage = stage; first_fail_cur = -1;
                first_fail_kind = "base";
            }
            continue;
        }

        for (int cur_stage = 0; cur_stage < stage - 1; cur_stage++) {
            if (min_stage_at_gram[gidx] > cur_stage + 1) {
                Bitmap* curr_v_bm = v_arr + cur_stage;
                if (!bitmap_test_gram(curr_v_bm, gram)) {
                    res = false;
                    n_fail_verif++;
                    if (first_fail_rid < 0) {
                        first_fail_rid = sr->assigns[i].rule_id;
                        first_fail_stage = stage; first_fail_cur = cur_stage;
                        first_fail_kind = "verifier";
                    }
                    break;
                }
            }

            uint8_t next_gram[3];
            memcpy(next_gram, next_grams + (cur_stage * 3), 3);

            Bitmap* curr_bm = b_arr + (cur_stage + 1);
            if (!bitmap_test_gram(curr_bm, next_gram)) {
                res = false;
                n_fail_next++;
                if (first_fail_rid < 0) {
                    first_fail_rid = sr->assigns[i].rule_id;
                    first_fail_stage = stage; first_fail_cur = cur_stage;
                    first_fail_kind = "next-stage";
                }
                break;
            }
        }
    }

    free(min_stage_at_gram);

    if (!res) {
        fprintf(stderr,
                "verify_ms_bitmap: fails  base=%d verifier=%d next-stage=%d ; "
                "first: rule=%d stage=%d cur=%d kind=%s\n",
                n_fail_base, n_fail_verif, n_fail_next,
                first_fail_rid, first_fail_stage, first_fail_cur,
                first_fail_kind ? first_fail_kind : "?");
    }
    return res;
}
