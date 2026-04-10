#include <stdlib.h>
#include "priority.h"

static const RuleSet *g_rs;

static const Rule *find_rule(const RuleSet *rs, int rule_id)
{
    for (int i = 0; i < rs->count; i++)
        if (rs->rules[i].id == rule_id)
            return &rs->rules[i];
    return NULL;
}

static int cmp_priority(const void *a, const void *b)
{
    const MatchResult *ma = (const MatchResult *)a;
    const MatchResult *mb = (const MatchResult *)b;
    const Rule *ra = find_rule(g_rs, ma->rule_id);
    const Rule *rb = find_rule(g_rs, mb->rule_id);
    int pa = ra ? ra->priority : 0;
    int pb = rb ? rb->priority : 0;
    return pb - pa;
}

void priority_sort(MatchResult *matches, int nm, const RuleSet *rs)
{
    if (nm <= 1) return;
    g_rs = rs;
    qsort(matches, (size_t)nm, sizeof(MatchResult), cmp_priority);
}
