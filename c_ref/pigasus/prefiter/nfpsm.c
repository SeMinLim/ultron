#include "nfpsm.h"
#include "types/hash.h"
#include "types/id_array.h"
#include <string.h>

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

static int find_rule_slot(const nfpsm *engine, uint32_t rule_id)
{
    for (size_t i = 0; i < (*engine).num_rules; i++) {
        if ((*engine).rules[i].rule_id == rule_id) {
            return (int)i;
        }
    }
    return -1;
}

static int add_pattern(nfpsm *engine, uint16_t rule_slot, const uint8_t *s, uint16_t len)
{
    if ((*engine).num_patterns >= NFPSM_MAX_PATTERNS) {
        return -1;
    }

    uint16_t eff_len = effective_len(len);
    uint8_t bucket = bucket_for_len(len);
    uint64_t key = hash_fnv1a64(s, eff_len);

    nfpsm_pattern *p = &(*engine).patterns[(*engine).num_patterns];
    (*p).bytes = s;
    (*p).len = eff_len;
    (*p).bucket = bucket;
    (*p).owner_rule_slot = rule_slot;
    (*p).next_same_hash = UINT16_MAX;

    uint64_t head_enc = 0;
    if (cuckoo_hash_lookup(&(*engine).buckets[bucket].hash_to_head, key, &head_enc)) {
        if (head_enc > 0 && head_enc <= NFPSM_MAX_PATTERNS) {
            (*p).next_same_hash = (uint16_t)(head_enc - 1);
        }
    }

    if (cuckoo_hash_insert(&(*engine).buckets[bucket].hash_to_head,
                           key,
                           (uint64_t)((*engine).num_patterns + 1)) != 0) {
        return -1;
    }

    if ((*engine).rules[rule_slot].num_pattern_indices >= NFPSM_MAX_STRINGS_PER_RULE) {
        return -1;
    }
    (*engine).rules[rule_slot].pattern_indices[(*engine).rules[rule_slot].num_pattern_indices++] =
        (uint16_t)(*engine).num_patterns;
    (*engine).num_patterns++;
    return 0;
}

int nfpsm_init(nfpsm *engine, const nfpsm_rule *rules, size_t num_rules)
{
    if (!engine || !rules || num_rules == 0 || num_rules > NFPSM_MAX_RULES) {
        return -1;
    }

    memset(engine, 0, sizeof(*engine));

    for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
        (*engine).buckets[b].len = (uint16_t)(b + 1);
        if (cuckoo_hash_init(&(*engine).buckets[b].hash_to_head, NFPSM_HASH_CAP) != 0) {
            nfpsm_free(engine);
            return -1;
        }
    }

    for (size_t r = 0; r < num_rules; r++) {
        if (rules[r].num_strings == 0 || rules[r].num_strings > NFPSM_MAX_STRINGS_PER_RULE) {
            nfpsm_free(engine);
            return -1;
        }

        (*engine).rules[(*engine).num_rules].rule_id = rules[r].rule_id;

        for (uint16_t s = 0; s < rules[r].num_strings; s++) {
            if (!rules[r].strings[s] || rules[r].lens[s] == 0) {
                nfpsm_free(engine);
                return -1;
            }
            if (add_pattern(engine,
                            (uint16_t)(*engine).num_rules,
                            rules[r].strings[s],
                            rules[r].lens[s]) != 0) {
                nfpsm_free(engine);
                return -1;
            }
        }

        for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
            (*engine).rules[(*engine).num_rules].fingerprint[b] = 0;
        }
        for (uint16_t j = 0; j < (*engine).rules[(*engine).num_rules].num_pattern_indices; j++) {
            uint16_t pat_slot = (*engine).rules[(*engine).num_rules].pattern_indices[j];
            uint8_t bucket = (*engine).patterns[pat_slot].bucket;
            (*engine).rules[(*engine).num_rules].fingerprint[bucket] |=
                (uint16_t)(1U << (pat_slot % NFPSM_FINGERPRINT_BITS));
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

    memset(engine, 0, sizeof(*engine));
}

static void build_packet_fingerprint(nfpsm *engine,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     uint16_t pkt_fp[NFPSM_BUCKETS])
{
    for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
        pkt_fp[b] = 0;
    }

    for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
        uint16_t len = (*engine).buckets[b].len;
        if (payload_len < len) {
            continue;
        }

        for (size_t i = 0; i + len <= payload_len; i++) {
            uint64_t key = hash_fnv1a64(payload + i, len);
            uint64_t head_enc = 0;
            if (!cuckoo_hash_lookup(&(*engine).buckets[b].hash_to_head, key, &head_enc) ||
                head_enc == 0 ||
                head_enc > NFPSM_MAX_PATTERNS) {
                continue;
            }

            uint16_t slot = (uint16_t)(head_enc - 1);
            while (slot < (*engine).num_patterns) {
                const nfpsm_pattern *pat = &(*engine).patterns[slot];
                if ((*pat).bucket == b && (*pat).len == len &&
                    memcmp(payload + i, (*pat).bytes, len) == 0) {
                    pkt_fp[b] |= (uint16_t)(1U << (slot % NFPSM_FINGERPRINT_BITS));
                }
                if ((*pat).next_same_hash == UINT16_MAX) {
                    break;
                }
                slot = (*pat).next_same_hash;
            }
        }
    }
}

static int rule_fingerprint_matches(const nfpsm_rule_state *rule,
                                    const uint16_t pkt_fp[NFPSM_BUCKETS])
{
    for (uint8_t b = 0; b < NFPSM_BUCKETS; b++) {
        if (((*rule).fingerprint[b] & pkt_fp[b]) != (*rule).fingerprint[b]) {
            return 0;
        }
    }
    return 1;
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
        int slot = find_rule_slot(engine, candidate_rule_ids[i]);
        if (slot < 0) {
            continue;
        }

        if (!rule_fingerprint_matches(&(*engine).rules[slot], pkt_fp)) {
            continue;
        }

        id_array_append_unique(out_rule_ids, &out_n, max_out, candidate_rule_ids[i]);
    }

    return out_n;
}
