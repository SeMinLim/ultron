#ifndef MATCH_H
#define MATCH_H

#include <stdint.h>
#include "bitmap.h"
#include "singleton.h"
#include "hashtable.h"

typedef struct {
    HashTable       *ht;
    SingletonResult *sr;
} MatchCtx;

#define MATCH_MAX_STAGES 8

typedef struct {
    int total;
    int hit;
} StageStat;

typedef struct {
    int       ngram_hit;
    int       nc;
    int       n_stages;
    StageStat stage[MATCH_MAX_STAGES];
    int       ht_total;
    int       ht_hit;
    int       cand_total;
    int       cand_hit;
} MatchCount;

typedef struct {
    int               anchor;
    const GramAssign *assign;
} MatchCandidate;

void match_init(MatchCtx *ctx, SingletonResult *sr);
void match_destroy(MatchCtx *ctx);

MatchCount  match_scan(const MatchCtx *ctx,
                const uint8_t *pkt, int pkt_len,
                const Bitmap *bm, const Bitmap *vm,
                MatchCandidate *out, int out_max, int max_stage);

#endif
