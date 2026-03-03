#include "nfpsm.h"
#include <stdlib.h>
#include <string.h>

static uint64_t hash64(const uint8_t *bytes, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static int append_unique_id(uint32_t *ids, size_t *count, size_t max_count, uint32_t id)
{
    if (!ids || !count) {
        return 0;
    }

    for (size_t i = 0; i < *count; i++) {
        if (ids[i] == id) {
            return 1;
        }
    }

    if (*count >= max_count) {
        return 0;
    }

    ids[(*count)++] = id;
    return 1;
}

static size_t next_pow2(size_t v)
{
    size_t p = NFPSM_MIN_HASH_CAP;
    while (p < v) {
        p <<= 1U;
    }
    return p;
}

static inline uint8_t bucket_for_len(uint16_t len)
{
    if (len == 0) {
        return 0;
    }
    return (uint8_t)((len > NFPSM_BUCKETS) ? (NFPSM_BUCKETS - 1) : (len - 1));
}

static inline uint16_t effective_len(uint16_t len)
{
    if (len == 0) {
        return 0;
    }
    return (uint16_t)((len > NFPSM_BUCKETS) ? NFPSM_BUCKETS : len);
}

static int find_rule_slot(const nfpsm *engine, uint32_t rule_id, uint32_t *out_slot)
{
    uint64_t enc = 0;
    if (!cuckoo_hash_lookup(&(*engine).rule_to_slot, rule_id, &enc) || enc == 0 ||
        enc > (*engine).num_rules) {
        return 0;
    }

    *out_slot = (uint32_t)(enc - 1);
    return 1;
}

static int add_pattern(nfpsm *engine, uint32_t rule_slot, const uint8_t *s, uint16_t len)
{
    if ((*engine).num_patterns >= NFPSM_MAX_PATTERNS) {
        return -1;
    }

    uint16_t eff_len = effective_len(len);
    uint8_t bucket = bucket_for_len(len);
    uint64_t key = hash64(s, eff_len);

    nfpsm_pattern *p = &(*engine).patterns[(*engine).num_patterns];
    (*p).bytes = s;
    (*p).len = eff_len;
    (*p).bucket = bucket;
    (*p).owner_rule_slot = rule_slot;
    (*p).next_same_hash = NFPSM_PATTERN_NONE;

    uint64_t head_enc = 0;
    if (cuckoo_hash_lookup(&(*engine).buckets[bucket].hash_to_head, key, &head_enc)) {
        if (head_enc > 0 && head_enc <= (*engine).num_patterns) {
            (*p).next_same_hash = (uint32_t)(head_enc - 1);
        }
    }

    if (cuckoo_hash_insert(&(*engine).buckets[bucket].hash_to_head,
                           key,
                           (uint64_t)((*engine).num_patterns + 1)) != 0) {
        return -1;
    }

    (*engine).rules[rule_slot].fingerprint[bucket] |=
        (uint16_t)(1U << ((*engine).num_patterns % NFPSM_FP_BITS));
    (*engine).num_patterns++;
    return 0;
}

int nfpsm_init(nfpsm *engine, const nfpsm_rule *rules, size_t num_rules)
{
    if (!engine || !rules || num_rules == 0 || num_rules > NFPSM_MAX_RULES) {
        return -1;
    }

    memset(engine, 0, sizeof(*engine));

    size_t total_patterns = 0;
    size_t bucket_counts[NFPSM_BUCKETS];
    memset(bucket_counts, 0, sizeof(bucket_counts));

    for (size_t r = 0; r < num_rules; r++) {
        if (rules[r].num_strings == 0 || rules[r].num_strings > NFPSM_MAX_STRINGS_PER_RULE) {
            nfpsm_free(engine);
            return -1;
        }

        total_patterns += rules[r].num_strings;
        if (total_patterns > NFPSM_MAX_PATTERNS) {
            nfpsm_free(engine);
            return -1;
        }

        for (uint16_t s = 0; s < rules[r].num_strings; s++) {
            if (!rules[r].strings[s] || rules[r].lens[s] == 0) {
                nfpsm_free(engine);
                return -1;
            }
            bucket_counts[bucket_for_len(rules[r].lens[s])]++;
        }
    }

    (*engine).rules = calloc(num_rules, sizeof(*(*engine).rules));
    (*engine).patterns = calloc(total_patterns, sizeof(*(*engine).patterns));
    if (!(*engine).rules || !(*engine).patterns) {
        nfpsm_free(engine);
        return -1;
    }

    if (cuckoo_hash_init(&(*engine).rule_to_slot, next_pow2(num_rules * 2U)) != 0) {
        nfpsm_free(engine);
        return -1;
    }

    for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
        (*engine).buckets[b].len = (uint16_t)(b + 1);
        if (cuckoo_hash_init(&(*engine).buckets[b].hash_to_head,
                             next_pow2(bucket_counts[b] * 2U)) != 0) {
            nfpsm_free(engine);
            return -1;
        }
    }

    for (size_t r = 0; r < num_rules; r++) {
        (*engine).rules[(*engine).num_rules].rule_id = rules[r].rule_id;

        if (cuckoo_hash_insert(&(*engine).rule_to_slot,
                               rules[r].rule_id,
                               (uint64_t)((*engine).num_rules + 1)) != 0) {
            nfpsm_free(engine);
            return -1;
        }

        for (uint16_t s = 0; s < rules[r].num_strings; s++) {
            if (add_pattern(engine,
                            (uint32_t)(*engine).num_rules,
                            rules[r].strings[s],
                            rules[r].lens[s]) != 0) {
                nfpsm_free(engine);
                return -1;
            }
        }

        (*engine).num_rules++;
    }

    (*engine).initialized = 1;
    return 0;
}

void nfpsm_free(nfpsm *engine)
{
    if (!engine) {
        return;
    }

    for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
        cuckoo_hash_free(&(*engine).buckets[b].hash_to_head);
    }
    cuckoo_hash_free(&(*engine).rule_to_slot);
    free((*engine).rules);
    free((*engine).patterns);

    memset(engine, 0, sizeof(*engine));
}

static void build_packet_fingerprint(const nfpsm *engine,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     uint16_t out_fp[NFPSM_BUCKETS])
{
    for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
        out_fp[b] = 0;
        uint16_t len = (*engine).buckets[b].len;
        if (payload_len < len) {
            continue;
        }

        for (size_t i = 0; i + len <= payload_len; i++) {
            uint64_t key = hash64(payload + i, len);
            uint64_t head_enc = 0;
            if (!cuckoo_hash_lookup(&(*engine).buckets[b].hash_to_head, key, &head_enc) ||
                head_enc == 0 ||
                head_enc > (*engine).num_patterns) {
                continue;
            }

            uint32_t slot = (uint32_t)(head_enc - 1);
            while (slot < (*engine).num_patterns) {
                const nfpsm_pattern *pat = &(*engine).patterns[slot];
                if ((*pat).bucket == b &&
                    (*pat).len == len &&
                    memcmp(payload + i, (*pat).bytes, len) == 0) {
                    out_fp[b] |= (uint16_t)(1U << (slot % NFPSM_FP_BITS));
                }

                if ((*pat).next_same_hash == NFPSM_PATTERN_NONE) {
                    break;
                }
                slot = (*pat).next_same_hash;
            }
        }
    }
}

size_t nfpsm_filter(nfpsm *engine,
                    const uint8_t *payload,
                    size_t payload_len,
                    const uint32_t *candidate_rule_ids,
                    size_t num_candidates,
                    uint32_t *out_rule_ids,
                    size_t max_out)
{
    if (!engine || !(*engine).initialized || !payload || !candidate_rule_ids || !out_rule_ids ||
        max_out == 0) {
        return 0;
    }

    uint16_t pkt_fp[NFPSM_BUCKETS];
    build_packet_fingerprint(engine, payload, payload_len, pkt_fp);

    size_t out_n = 0;
    for (size_t i = 0; i < num_candidates && out_n < max_out; i++) {
        uint32_t slot = 0;
        if (!find_rule_slot(engine, candidate_rule_ids[i], &slot)) {
            continue;
        }

        int ok = 1;
        for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
            uint16_t rf = (*engine).rules[slot].fingerprint[b];
            if ((rf & pkt_fp[b]) != rf) {
                ok = 0;
                break;
            }
        }
        if (!ok) {
            continue;
        }

        append_unique_id(out_rule_ids, &out_n, max_out, candidate_rule_ids[i]);
    }

    return out_n;
}

#ifdef NFPSM_TEST
#include <stdio.h>

int main(void)
{
    nfpsm engine;
    nfpsm_rule rules[2];
    uint32_t candidates[2] = { 200, 201 };
    uint32_t out[8];
    size_t n;

    memset(rules, 0, sizeof(rules));

    rules[0].rule_id = 200;
    rules[0].strings[0] = (const uint8_t *)"cmd";
    rules[0].lens[0] = 3;
    rules[0].strings[1] = (const uint8_t *)"exec";
    rules[0].lens[1] = 4;
    rules[0].num_strings = 2;

    rules[1].rule_id = 201;
    rules[1].strings[0] = (const uint8_t *)"abc";
    rules[1].lens[0] = 3;
    rules[1].strings[1] = (const uint8_t *)"zzzz";
    rules[1].lens[1] = 4;
    rules[1].num_strings = 2;

    if (nfpsm_init(&engine, rules, 2) != 0) {
        fprintf(stderr, "nfpsm: init failed\n");
        return 1;
    }

    n = nfpsm_filter(&engine,
                     (const uint8_t *)"___cmd____exec___",
                     16,
                     candidates,
                     2,
                     out,
                     8);
    if (n != 1 || out[0] != 200) {
        fprintf(stderr, "nfpsm: match case failed (n=%zu)\n", n);
        nfpsm_free(&engine);
        return 1;
    }

    n = nfpsm_filter(&engine,
                     (const uint8_t *)"___abc____zzzz___",
                     16,
                     candidates,
                     2,
                     out,
                     8);
    if (n != 1 || out[0] != 201) {
        fprintf(stderr, "nfpsm: second rule case failed (n=%zu)\n", n);
        nfpsm_free(&engine);
        return 1;
    }

    nfpsm_free(&engine);
    printf("nfpsm: all tests passed\n");
    return 0;
}
#endif
