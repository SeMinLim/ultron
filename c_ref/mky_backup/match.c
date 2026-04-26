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

    int per_bank[HT_BANKS] = {0};
    for (int i = 0; i < sr->count; i++) {
        if (i > 0 && sr->assigns[i].gram_idx == sr->assigns[i - 1].gram_idx)
            continue;
        per_bank[sr->assigns[i].gram_idx & HT_BANK_MASK]++;
    }

    for (int b = 0; b < HT_BANKS; b++) {
        int cap = per_bank[b] * 2;
        if (cap < 16) cap = 16;

        for (int attempt = 0; attempt < 8; attempt++) {
            ctx->banks[b] = ht_create(cap);
            int ok = 1;
            for (int i = 0; i < sr->count; i++) {
                int gidx = (int)sr->assigns[i].gram_idx;
                if ((gidx & HT_BANK_MASK) != b) continue;
                int subkey = gidx >> 2;
                int existing;
                if (ht_lookup(ctx->banks[b], subkey, &existing)) continue;
                if (!ht_insert(ctx->banks[b], subkey, i)) { ok = 0; break; }
            }
            if (ok) break;
            ht_destroy(ctx->banks[b]);
            cap *= 2;
        }
    }
}

void match_destroy(MatchCtx *ctx)
{
    for (int b = 0; b < HT_BANKS; b++) {
        ht_destroy(ctx->banks[b]);
        ctx->banks[b] = NULL;
    }
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
        int bank = gidx & HT_BANK_MASK;
        int subkey = gidx >> 2;
        int base;
        res.ht_total++;
        res.bank_lookups[bank]++;
        if (!ht_lookup(ctx->banks[bank], subkey, &base))
            continue;
        res.ht_hit++;
        res.bank_hits[bank]++;

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
