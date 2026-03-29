#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "singleton.h"

typedef struct { uint32_t *v; int n, cap; } U32Vec;

static void vec_push(U32Vec *v, uint32_t x)
{
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->v   = realloc(v->v, v->cap * sizeof(uint32_t));
    }
    v->v[v->n++] = x;
}

static int vec_has(const U32Vec *v, uint32_t x)
{
    for (int i = 0; i < v->n; i++)
        if (v->v[i] == x) return 1;
    return 0;
}

#define HT_EMPTY 0xFFFFFFFFU

typedef struct {
    uint32_t gram_idx;
    int     *rule_ids;
    int      count;
    int      cap;
    int      degree;
    int      gone;
} GNode;

typedef struct {
    GNode *slots;
    int    size;
} GHT;

static GHT *ght_new(int min_size)
{
    int s = 1;
    while (s < min_size * 2) s <<= 1;
    GHT *ht   = malloc(sizeof *ht);
    ht->slots  = malloc(s * sizeof(GNode));
    for (int i = 0; i < s; i++) ht->slots[i].gram_idx = HT_EMPTY;
    ht->size   = s;
    return ht;
}

static GNode *ght_slot(GHT *ht, uint32_t idx)
{
    int mask = ht->size - 1;
    int pos  = (int)(idx & (uint32_t)mask);
    while (ht->slots[pos].gram_idx != HT_EMPTY &&
           ht->slots[pos].gram_idx != idx)
        pos = (pos + 1) & mask;
    return &ht->slots[pos];
}

static GNode *ght_find(GHT *ht, uint32_t idx)
{
    GNode *n = ght_slot(ht, idx);
    return (n->gram_idx == idx) ? n : NULL;
}

static GNode *ght_insert(GHT *ht, uint32_t idx)
{
    GNode *n = ght_slot(ht, idx);
    if (n->gram_idx == HT_EMPTY)
        *n = (GNode){ idx, NULL, 0, 0, 0, 0 };
    return n;
}

static void gnode_add_rule(GNode *n, int rid)
{
    if (n->count == n->cap) {
        n->cap      = n->cap ? n->cap * 2 : 4;
        n->rule_ids = realloc(n->rule_ids, n->cap * sizeof(int));
    }
    n->rule_ids[n->count++] = rid;
    n->degree++;
}

static void ght_free(GHT *ht)
{
    for (int i = 0; i < ht->size; i++)
        free(ht->slots[i].rule_ids);
    free(ht->slots);
    free(ht);
}

static inline uint32_t pack3(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

SingletonResult *singleton_build(const RuleSet *rs)
{
    int nr  = rs->count;
    int est = 0;
    for (int i = 0; i < nr; i++)
        if (rs->rules[i].pat_len >= 3)
            est += rs->rules[i].pat_len - 2;

    GHT    *ht         = ght_new(est + 64);
    U32Vec *rule_grams = calloc(nr, sizeof(U32Vec));
    int    *rule_sel   = malloc(nr * sizeof(int));
    int    *rule_cov   = calloc(nr, sizeof(int));
    memset(rule_sel, -1, nr * sizeof(int));

    /* step 1: build bipartite graph */
    for (int rid = 0; rid < nr; rid++) {
        const Rule *r = &rs->rules[rid];
        if (r->pat_len < 3) continue;
        for (int i = 0; i <= r->pat_len - 3; i++) {
            uint32_t idx = pack3((const uint8_t *)r->pattern + i);
            if (vec_has(&rule_grams[rid], idx)) continue;
            vec_push(&rule_grams[rid], idx);
            gnode_add_rule(ght_insert(ht, idx), rid);
        }
    }

    int n_uncov = 0;
    for (int i = 0; i < nr; i++)
        if (rs->rules[i].pat_len >= 3) n_uncov++;

    /* step 2: greedy degree-peeling */
    int       qcap  = est * 2 + ht->size + 1;
    uint32_t *queue = malloc(qcap * sizeof(uint32_t));
    int       qhead = 0, qtail = 0;

    for (int i = 0; i < ht->size; i++) {
        GNode *n = &ht->slots[i];
        if (n->gram_idx != HT_EMPTY && n->degree == 1)
            queue[qtail++] = n->gram_idx;
    }

    while (n_uncov > 0) {
        GNode   *sel  = NULL;
        uint32_t sidx = 0;

        while (qhead < qtail) {
            uint32_t gi = queue[qhead++];
            GNode   *n  = ght_find(ht, gi);
            if (n && !n->gone && n->degree > 0) { sel = n; sidx = gi; break; }
        }

        if (!sel) {
            int best = INT_MAX;
            for (int i = 0; i < ht->size; i++) {
                GNode *n = &ht->slots[i];
                if (n->gram_idx == HT_EMPTY || n->gone || n->degree == 0) continue;
                if (n->degree < best) { best = n->degree; sel = n; sidx = n->gram_idx; }
            }
            if (!sel) break;
        }

        sel->gone = 1;

        for (int j = 0; j < sel->count; j++) {
            int rid = sel->rule_ids[j];
            if (rule_cov[rid]) continue;
            rule_cov[rid] = 1;
            rule_sel[rid] = (int)sidx;
            n_uncov--;

            for (int k = 0; k < rule_grams[rid].n; k++) {
                uint32_t other = rule_grams[rid].v[k];
                if (other == sidx) continue;
                GNode *on = ght_find(ht, other);
                if (!on || on->gone) continue;
                on->degree--;
                if (on->degree == 1 && qtail < qcap)
                    queue[qtail++] = other;
            }
        }
    }

    /* build output */
    int n_covered = 0, n_skipped = 0;
    for (int i = 0; i < nr; i++) {
        if (rule_cov[i]) n_covered++;
        else             n_skipped++;
    }

    SingletonResult *res = malloc(sizeof *res);
    res->assigns   = malloc(n_covered * sizeof(GramAssign));
    res->count     = 0;
    res->uncovered = n_skipped;

    for (int rid = 0; rid < nr; rid++) {
        if (!rule_cov[rid]) continue;
        const Rule *r    = &rs->rules[rid];
        uint32_t    gi   = (uint32_t)rule_sel[rid];
        GNode      *node = ght_find(ht, gi);

        int gram_pos = 0;
        for (int i = 0; i <= r->pat_len - 3; i++) {
            if (pack3((const uint8_t *)r->pattern + i) == gi) { gram_pos = i; break; }
        }

        GramAssign *a  = &res->assigns[res->count++];
        a->gram_idx    = gi;
        a->gram[0]     = (uint8_t)(gi >> 16);
        a->gram[1]     = (uint8_t)(gi >>  8);
        a->gram[2]     = (uint8_t)(gi      );
        a->rule_id     = r->id;
        a->gram_pos    = gram_pos;
        a->pre_offset  = -gram_pos;
        a->post_offset = r->pat_len - gram_pos - 3;
        a->degree      = node ? node->count : 1;
    }

    for (int i = 0; i < nr; i++) free(rule_grams[i].v);
    free(rule_grams);
    free(rule_sel);
    free(rule_cov);
    free(queue);
    ght_free(ht);

    return res;
}

void singleton_free(SingletonResult *r)
{
    if (!r) return;
    free(r->assigns);
    free(r);
}
