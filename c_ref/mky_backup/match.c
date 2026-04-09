#include <stdlib.h>
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

int match_scan(const MatchCtx *ctx,
               const uint8_t *pkt, int pkt_len,
               const Bitmap *bm,
               MatchCandidate *out, int out_max)
{
    int n = 0;

    for (int anchor = 0; anchor <= pkt_len - 3; anchor++) {
        if (!bitmap_test_gram(bm, pkt + anchor))
            continue;

        int gidx = (int)bitmap_idx(pkt + anchor);

        int base;
        if (!ht_lookup(ctx->ht, gidx, &base))
            continue;

        for (int j = base;
             j < ctx->sr->count && ctx->sr->assigns[j].gram_idx == (uint32_t)gidx;
             j++) {
            if (n < out_max)
                out[n] = (MatchCandidate){ anchor, &ctx->sr->assigns[j] };
            n++;
        }
    }

    return n;
}
