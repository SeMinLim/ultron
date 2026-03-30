#ifndef EXACT_MATCH_H
#define EXACT_MATCH_H

#include <stdint.h>
#include "match.h"
#include "rule_loader.h"

typedef struct {
    int rule_id;
    int anchor;
} MatchResult;

int exact_match(const uint8_t *pkt, int pkt_len,
                const MatchCandidate *candidates, int n_candidates,
                const RuleSet *rs,
                MatchResult *out, int out_max);

#endif
