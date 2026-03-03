#ifndef NFPSM_H
#define NFPSM_H

#include "types/cuckoo_hash.h"
#include <stddef.h>
#include <stdint.h>

#define NFPSM_BUCKETS 8
#define NFPSM_MIN_HASH_CAP 16
#define NFPSM_FP_BITS 16

#define NFPSM_MAX_RULES 65536
#define NFPSM_MAX_STRINGS_PER_RULE 32
#define NFPSM_MAX_PATTERNS 2097152
#define NFPSM_PATTERN_NONE UINT32_MAX

typedef struct {
    uint32_t rule_id;
    const uint8_t *strings[NFPSM_MAX_STRINGS_PER_RULE];
    uint16_t lens[NFPSM_MAX_STRINGS_PER_RULE];
    uint16_t num_strings;
} nfpsm_rule;

typedef struct {
    const uint8_t *bytes;
    uint16_t len;
    uint8_t bucket;
    uint32_t owner_rule_slot;
    uint32_t next_same_hash;
} nfpsm_pattern;

typedef struct {
    uint16_t len;
    cuckoo_hash_t hash_to_head;
} nfpsm_bucket;

typedef struct {
    uint32_t rule_id;
    uint16_t fingerprint[NFPSM_BUCKETS];
} nfpsm_rule_state;

typedef struct {
    nfpsm_bucket buckets[NFPSM_BUCKETS];
    cuckoo_hash_t rule_to_slot;
    nfpsm_rule_state *rules;
    nfpsm_pattern *patterns;
    size_t num_rules;
    size_t num_patterns;
    int initialized;
} nfpsm;

int nfpsm_init(nfpsm *engine, const nfpsm_rule *rules, size_t num_rules);

void nfpsm_free(nfpsm *engine);

size_t nfpsm_filter(nfpsm *engine,
                    const uint8_t *payload,
                    size_t payload_len,
                    const uint32_t *candidate_rule_ids,
                    size_t num_candidates,
                    uint32_t *out_rule_ids,
                    size_t max_out);

#endif
