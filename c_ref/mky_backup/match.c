#include <stdlib.h>
#include <string.h>
#include "match.h"

static int cmp_by_gram_idx(const void *a, const void *b)
{
    const GramAssign *x = (const GramAssign *)a;
    const GramAssign *y = (const GramAssign *)b;
    if (x->gram_idx < y->gram_idx) return -1;
    if (x->gram_idx > y->gram_idx) return  1;
    return 0;
}

void match_init(MatchCtx *ctx, SingletonResult *sr)
{
    qsort(sr->assigns, sr->count, sizeof(GramAssign), cmp_by_gram_idx);

    ctx->sr = sr;
    ctx->ht = ht_create(sr->count * 2);

    for (int i = 0; i < sr->count; i++) {
        int gidx = (int)sr->assigns[i].gram_idx;
        int existing;
        if (!ht_lookup(ctx->ht, gidx, &existing))
            ht_insert(ctx->ht, gidx, i);
    }
}

void match_destroy(MatchCtx *ctx)
{
    ht_destroy(ctx->ht);
    ctx->ht = NULL;
    ctx->sr = NULL;
}

MatchCount match_scan(const MatchCtx *ctx,
               const uint8_t *pkt, int pkt_len,
               const Bitmap *bm, const Bitmap *vm,
               MatchCandidate *out, int out_max, int max_stage)
{
    MatchCount res = {0, 0};

    for (int anchor = 0; anchor <= pkt_len - 3; anchor++) {
        const uint8_t *gram = pkt + anchor;

        if (!bitmap_test_gram(bm, gram))
            continue;

        int viable_stage = 1;
        for (int s = 0; s < max_stage - 1; s++) {
            if (!bitmap_test_gram(vm + s, gram))
                break;
            int next_anchor = anchor + (s + 1) * 3;
            if (next_anchor + 3 > pkt_len)
                break;
            if (!bitmap_test_gram(bm + s + 1, pkt + next_anchor))
                break;
            viable_stage = s + 2;
        }

        int gidx = (int)bitmap_idx(gram);
        int base;
        if (!ht_lookup(ctx->ht, gidx, &base))
            continue;

        int anchor_hit = 0;
        for (int j = base;
             j < ctx->sr->count && ctx->sr->assigns[j].gram_idx == (uint32_t)gidx;
             j++) {
            if (ctx->sr->assigns[j].stage > viable_stage)
                continue;
            anchor_hit = 1;
            if (res.nc < out_max)
                out[res.nc] = (MatchCandidate){ anchor, &ctx->sr->assigns[j] };
            res.nc++;
        }

        if (anchor_hit)
            res.ngram_hit++;
    }
    return res;
}
