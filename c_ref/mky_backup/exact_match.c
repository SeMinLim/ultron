#include <string.h>
#include "exact_match.h"

static const Rule *find_rule(const RuleSet *rs, int rule_id)
{
    for (int i = 0; i < rs->count; i++)
        if (rs->rules[i].id == rule_id)
            return &rs->rules[i];
    return NULL;
}

int exact_match(const uint8_t *pkt, int pkt_len,
                const MatchCandidate *candidates, int n_candidates,
                const RuleSet *rs,
                MatchResult *out, int out_max)
{
    int n = 0;

    for (int i = 0; i < n_candidates; i++) {
        int               anchor = candidates[i].anchor;
        const GramAssign *a      = candidates[i].assign;

        int start = anchor + a->pre_offset;
        int end   = anchor + 3 + a->post_offset;

        if (start < 0 || end > pkt_len)
            continue;

        const Rule *r = find_rule(rs, a->rule_id);
        if (!r) continue;

        if ((end - start) == r->pat_len &&
            memcmp(pkt + start, r->pattern, (size_t)r->pat_len) == 0) {
            if (n < out_max)
                out[n] = (MatchResult){ a->rule_id, anchor, start };
            n++;
        }
    }

    return n;
}
