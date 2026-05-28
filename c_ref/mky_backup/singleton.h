#ifndef SINGLETON_H
#define SINGLETON_H

#include <stdint.h>
#include "rule_loader.h"

typedef struct {
    uint32_t gram_idx;
    uint8_t  gram[3];
    int      rule_id;
    int      gram_pos;
    int      pre_offset;
    int      post_offset;
    int      degree;

    int      stage;
    uint8_t* next_grams;

    // 36-bit combined hashtable key: (gram_idx << 18) | next_gram_idx.
    // For mixed/stage1 groups (min_stage==1), next_gram_idx is forced to 0.
    // Computed by match_init() after singleton_build() returns.
    uint64_t ht_key;
} GramAssign;

typedef struct {
    GramAssign *assigns;
    int         count;
    int         uncovered;
} SingletonResult;

SingletonResult     *singleton_build(const RuleSet *rs, int max_stage);
void                singleton_free(SingletonResult *r);

#endif
