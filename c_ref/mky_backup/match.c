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
    MatchCount res = {0};
    res.n_stages = max_stage < MATCH_MAX_STAGES ? max_stage : MATCH_MAX_STAGES;

    for (int anchor = 0; anchor <= pkt_len - 3; anchor++) {
        const uint8_t *gram = pkt + anchor;

        res.stage[0].total++;
        if (!bitmap_test_gram(bm, gram))
            continue;
        res.stage[0].hit++;

        int viable_stage = 1;
        int chain_broke = 0;
        for (int s = 0; s < max_stage - 1 && s + 1 < MATCH_MAX_STAGES; s++) {
            res.stage[s + 1].total++;
            if (!bitmap_test_gram(vm + s, gram))
                break;
            int next_anchor = anchor + (s + 1) * 3;
            if (next_anchor + 3 > pkt_len) {
                chain_broke = 1;
                break;
            }
            if (!bitmap_test_gram(bm + s + 1, pkt + next_anchor)) {
                chain_broke = 1;
                break;
            }
            res.stage[s + 1].hit++;
            viable_stage = s + 2;
        }

        if (chain_broke)
            continue;

        int gidx = (int)bitmap_idx(gram);
        int base;
        res.ht_total++;
        if (!ht_lookup(ctx->ht, gidx, &base))
            continue;
        res.ht_hit++;

        int anchor_hit = 0;
        for (int j = base;
             j < ctx->sr->count && ctx->sr->assigns[j].gram_idx == (uint32_t)gidx;
             j++) {
            res.cand_total++;
            if (ctx->sr->assigns[j].stage > viable_stage)
                continue;
            res.cand_hit++;
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
