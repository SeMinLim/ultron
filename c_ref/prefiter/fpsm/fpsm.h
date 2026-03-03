#ifndef FPSM_H
#define FPSM_H

#include "bucket_shift_or.h"
#include "../types/cuckoo_hash.h"
#include "../types/rule_reduction.h"
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define FPSM_MAX_RULES 65536
#define FPSM_MAX_PATTERN_LEN 64
#define FPSM_MIN_HASH_CAP 16

#define FPSM_POSTING_NONE UINT32_MAX

typedef struct {
    const uint8_t *pattern;
    size_t len;
    uint32_t rule_id;
} fpsm_rule;

typedef struct {
    cuckoo_hash_t filter;
    cuckoo_hash_t index;
    int initialized;
} fpsm_stage;

typedef struct {
    uint32_t rule_slot;
    uint32_t next;
} fpsm_posting;

typedef struct {
    shift_or_bucket_t buckets[FPSM_MAX_PATTERN_LEN + 1];
    fpsm_stage stages[FPSM_MAX_PATTERN_LEN + 1];
    uint8_t used[FPSM_MAX_PATTERN_LEN + 1];
    uint8_t lens[FPSM_MAX_PATTERN_LEN];
    uint8_t lens_count;
    fpsm_rule *rules;
    fpsm_posting *postings;
    rule_reduction_t reducer;
    size_t num_rules;
    size_t num_postings;
    int initialized;
} fpsm;

int fpsm_init(fpsm *engine, const fpsm_rule *rules, size_t num_rules);

void fpsm_free(fpsm *engine);

size_t fpsm_scan(fpsm *engine, const uint8_t *buf, size_t buf_len,
                 uint32_t *out_rule_ids, size_t max_out);

#endif
