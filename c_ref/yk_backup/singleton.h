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
} GramAssign;

typedef struct {
    GramAssign *assigns;
    int         count;
    int         uncovered;
} SingletonResult;

SingletonResult *singleton_build(const RuleSet *rs);
void             singleton_free(SingletonResult *r);

#endif
