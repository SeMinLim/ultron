#ifndef FPSM_H
#define FPSM_H

#include "bucket_shift_or.h"
#include "../types/cuckoo_hash.h"
#include "../types/rule_reduction.h"
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define FPSM_MAX_RULES 64
#define FPSM_MAX_PATTERN_LEN 64
#define FPSM_HASH_CAP 1024
#define FPSM_FILTER_BITS 4096
#define FPSM_PREFILTER_MAX_LEN SHIFT_OR_PARALLEL

typedef struct {
    const uint8_t *pattern;
    size_t len;
    uint32_t rule_id;
} fpsm_rule;

typedef struct {
    const uint8_t *pattern;
    size_t len;
    uint8_t prefilter_len;
    uint8_t prefilter_bucket;
    uint32_t rule_id;
} fpsm_compiled_rule;

typedef struct {
    uint8_t *filter_bitset;
    cuckoo_hash_t bucket_tables[SHIFT_OR_BUCKETS];
    uint8_t used_buckets;
    int initialized;
} fpsm_stage;

typedef struct {
    shift_or_bucket_t buckets[FPSM_MAX_PATTERN_LEN + 1];
    fpsm_stage stages[FPSM_MAX_PATTERN_LEN + 1];
    uint8_t used[FPSM_MAX_PATTERN_LEN + 1];
    uint8_t lens[FPSM_MAX_PATTERN_LEN];
    uint8_t lens_count;
    fpsm_compiled_rule rules[FPSM_MAX_RULES];
    rule_reduction_t reducer;
    size_t num_rules;
    int initialized;
} fpsm;

int fpsm_init(fpsm *engine, const fpsm_rule *rules, size_t num_rules);

void fpsm_free(fpsm *engine);

size_t fpsm_scan(fpsm *engine, const uint8_t *buf, size_t buf_len,
                 uint32_t *out_rule_ids, size_t max_out);

#endif
