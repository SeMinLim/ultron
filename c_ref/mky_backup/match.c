#include <stdlib.h>
#include <string.h>
#include "match.h"
#include "xor_filter.h"

static int cmp_by_ht_key(const void *a, const void *b)
{
    const GramAssign *x = (const GramAssign *)a;
    const GramAssign *y = (const GramAssign *)b;
    if (x->ht_key < y->ht_key) return -1;
    if (x->ht_key > y->ht_key) return  1;
    return 0;
}

// Bank is selected from gidx0 (anchor gram only) so mixed/pure-stage2 groups
// that share gidx0 always land in the same bank — keeping bank count stable.
static int bank_of(uint64_t key)
{
    uint32_t gidx0 = (uint32_t)(key >> 18);
    return (int)((uint32_t)xor_murmur64(gidx0) & HT_BANK_MASK);
}

void match_init(MatchCtx *ctx, SingletonResult *sr)
{
    // Step 1: compute min_stage per gram_idx across all rules sharing that gram.
    // BITMAP_BITS = 2^18, one byte per possible gram_idx.
    uint8_t *min_stage = malloc(BITMAP_BITS);
    memset(min_stage, 0xff, BITMAP_BITS);
    for (int i = 0; i < sr->count; i++) {
        uint32_t g = sr->assigns[i].gram_idx;
        int s = sr->assigns[i].stage;
        if (s < min_stage[g])
            min_stage[g] = (uint8_t)(s > 254 ? 254 : s);
    }

    // Step 2: assign ht_key per rule.
    //   pure stage2 group (min_stage >= 2): key = (gidx0 << 18) | gidx1
    //   mixed/stage1 group (min_stage == 1): key = (gidx0 << 18) | 0
    // This way rules in mixed groups are all reachable via the anchor-only path,
    // while pure stage2 groups are split by their next gram for fewer candidates.
    for (int i = 0; i < sr->count; i++) {
        uint32_t gidx0 = sr->assigns[i].gram_idx;
        uint32_t gidx1 = 0;
        if (min_stage[gidx0] >= 2 && sr->assigns[i].next_grams != NULL)
            gidx1 = bitmap_idx(sr->assigns[i].next_grams);
        sr->assigns[i].ht_key = ((uint64_t)gidx0 << 18) | gidx1;
    }
    free(min_stage);

    // Step 3: sort assigns by ht_key so the chain walk can stop on key change.
    qsort(sr->assigns, sr->count, sizeof(GramAssign), cmp_by_ht_key);

    ctx->sr = sr;

    // Step 4: count unique keys per bank for capacity estimation.
    int per_bank[HT_BANKS] = {0};
    for (int i = 0; i < sr->count; i++) {
        if (i > 0 && sr->assigns[i].ht_key == sr->assigns[i - 1].ht_key)
            continue;
        per_bank[bank_of(sr->assigns[i].ht_key)]++;
    }

    // Step 5: build per-bank cuckoo hashtables. key=ht_key, val=first assign idx.
    for (int b = 0; b < HT_BANKS; b++) {
        int cap = per_bank[b] * 2;
        if (cap < 16) cap = 16;

        for (int attempt = 0; attempt < 8; attempt++) {
            ctx->banks[b] = ht_create(cap);
            int ok = 1;
            for (int i = 0; i < sr->count; i++) {
                uint64_t key = sr->assigns[i].ht_key;
                if (bank_of(key) != b) continue;
                int existing;
                if (ht_lookup(ctx->banks[b], key, &existing)) continue;
                if (!ht_insert(ctx->banks[b], key, i)) { ok = 0; break; }
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

        int  chain_broke      = 0;
        bool stage2_verified  = false;
        int  next_anchor_s2   = -1;

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
            if (s == 0) {
                stage2_verified = true;
                next_anchor_s2  = next_anchor;
            }
        }

        if (chain_broke)
            continue;

        uint32_t gidx0 = bitmap_idx(gram);
        uint32_t gidx1 = stage2_verified
                         ? bitmap_idx(pkt + next_anchor_s2)
                         : 0;
        uint64_t key   = ((uint64_t)gidx0 << 18) | gidx1;
        int      bank  = bank_of(key);
        int      base;

        res.ht_total++;
        res.bank_lookups[bank]++;
        if (!ht_lookup(ctx->banks[bank], key, &base))
            continue;
        res.ht_hit++;
        res.bank_hits[bank]++;

        int anchor_hit = 0;
        for (int j = base;
             j < ctx->sr->count && ctx->sr->assigns[j].ht_key == key;
             j++) {
            res.cand_total++;
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
