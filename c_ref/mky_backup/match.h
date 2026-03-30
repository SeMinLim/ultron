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

typedef struct {
    int               anchor;
    const GramAssign *assign;
} MatchCandidate;

void match_init(MatchCtx *ctx, SingletonResult *sr);
void match_destroy(MatchCtx *ctx);

int  match_scan(const MatchCtx *ctx,
                const uint8_t *pkt, int pkt_len,
                const Bitmap *bm,
                MatchCandidate *out, int out_max);

#endif
