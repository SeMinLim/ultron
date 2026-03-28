#include "fpsm.h"
#include "bucket_shift_or.h"
#include "../types/hash.h"
#include "../types/id_array.h"
#include <stdlib.h>
#include <string.h>

static uint8_t prefilter_len_for_rule(size_t len)
{
    if (len == 0) {
        return 0;
    }
    if (len > FPSM_PREFILTER_MAX_LEN) {
        return FPSM_PREFILTER_MAX_LEN;
    }
    return (uint8_t)len;
}

static const uint8_t *prefilter_ptr_for_rule(const fpsm_rule *r, uint8_t prefilter_len)
{
    (void)prefilter_len;
    return (*r).pattern;
}

static int stage_init(fpsm_stage *s)
{
    if (!s) {
        return -1;
    }

    memset(s, 0, sizeof(*s));

    (*s).filter_bitset = calloc(FPSM_FILTER_BITS / 8, 1);
    if (!(*s).filter_bitset) {
        return -1;
    }

    for (uint8_t bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
        if (cuckoo_hash_init(&(*s).bucket_tables[bucket], FPSM_HASH_CAP) != 0) {
            for (uint8_t prev = 0; prev < bucket; prev++) {
                cuckoo_hash_free(&(*s).bucket_tables[prev]);
            }
            free((*s).filter_bitset);
            (*s).filter_bitset = NULL;
            return -1;
        }
    }

    (*s).initialized = 1;
    return 0;
}

static void stage_free(fpsm_stage *s)
{
    if (!s) {
        return;
    }

    if ((*s).initialized) {
        free((*s).filter_bitset);
        (*s).filter_bitset = NULL;
        for (uint8_t bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
            cuckoo_hash_free(&(*s).bucket_tables[bucket]);
        }
    }

    memset(s, 0, sizeof(*s));
}

static void filter_bitset_set(uint8_t *bitset, uint64_t key)
{
    size_t idx = (size_t)(key % FPSM_FILTER_BITS);
    bitset[idx / 8] |= (uint8_t)(1U << (idx % 8));
}

static int filter_bitset_test(const uint8_t *bitset, uint64_t key)
{
    size_t idx = (size_t)(key % FPSM_FILTER_BITS);
    return (bitset[idx / 8] & (1U << (idx % 8))) != 0;
}

static int stage_add(fpsm_stage *s, uint64_t key, uint32_t rule_slot, uint8_t bucket)
{
    if (!s || !(*s).initialized || rule_slot >= 64 || bucket >= SHIFT_OR_BUCKETS) {
        return -1;
    }

    filter_bitset_set((*s).filter_bitset, key);

    uint64_t bit = 1ULL << rule_slot;
    uint64_t mask = 0;

    if (cuckoo_hash_lookup(&(*s).bucket_tables[bucket], key, &mask)) {
        mask |= bit;
    } else {
        mask = bit;
    }

    (*s).used_buckets |= (uint8_t)(1U << bucket);

    return cuckoo_hash_insert(&(*s).bucket_tables[bucket], key, mask);
}

static int stage_get(const fpsm_stage *s,
                     uint64_t key,
                     uint8_t bucket_bitmap,
                     uint64_t *rule_mask)
{
    if (!s || !(*s).initialized || !rule_mask) {
        return 0;
    }

    if (!filter_bitset_test((*s).filter_bitset, key)) {
        return 0;
    }

    uint64_t merged = 0;
    int found = 0;
    uint8_t active = (uint8_t)(bucket_bitmap & (*s).used_buckets);

    for (uint8_t bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
        if ((active & (1U << bucket)) == 0) {
            continue;
        }

        uint64_t mask = 0;
        if (cuckoo_hash_lookup(&(*s).bucket_tables[bucket], key, &mask)) {
            merged |= mask;
            found = 1;
        }
    }

    *rule_mask = merged;
    return found;
}

int fpsm_init(fpsm *engine, const fpsm_rule *rules, size_t num_rules)
{
    if (!engine || !rules || num_rules == 0 || num_rules > FPSM_MAX_RULES) {
        return -1;
    }

    memset(engine, 0, sizeof(*engine));

    for (size_t i = 0; i < num_rules; i++) {
        if (!rules[i].pattern || rules[i].len == 0 ||
            rules[i].len > FPSM_MAX_PATTERN_LEN ||
            rules[i].len > SHIFT_OR_MAX_PATTERN_LEN) {
            fpsm_free(engine);
            return -1;
        }

        uint8_t prefilter_len = prefilter_len_for_rule(rules[i].len);
        const uint8_t *prefilter_ptr = prefilter_ptr_for_rule(&rules[i], prefilter_len);
        uint32_t len = (uint32_t)prefilter_len;
        uint64_t key = hash_fnv1a64(prefilter_ptr, prefilter_len);
        uint8_t prefilter_bucket = 0;

        if (!(*engine).used[len]) {
            shiftOrBucketInit(&(*engine).buckets[len], prefilter_ptr, prefilter_len);
            if ((*engine).buckets[len].pattern_len == 0) {
                fpsm_free(engine);
                return -1;
            }
            if (stage_init(&(*engine).stages[len]) != 0) {
                fpsm_free(engine);
                return -1;
            }
            (*engine).used[len] = 1;
            (*engine).lens[(*engine).lens_count++] = (uint8_t)len;
        } else {
            if (shiftOrBucketAddPatternWithBucket(&(*engine).buckets[len],
                                                  prefilter_ptr,
                                                  prefilter_len,
                                                  &prefilter_bucket) != 0) {
                fpsm_free(engine);
                return -1;
            }
        }

        (*engine).rules[(*engine).num_rules].pattern = rules[i].pattern;
        (*engine).rules[(*engine).num_rules].len = rules[i].len;
        (*engine).rules[(*engine).num_rules].prefilter_len = prefilter_len;
        (*engine).rules[(*engine).num_rules].prefilter_bucket = prefilter_bucket;
        (*engine).rules[(*engine).num_rules].rule_id = rules[i].rule_id;
        (*engine).num_rules++;

        if (stage_add(&(*engine).stages[len],
                      key,
                      (uint32_t)((*engine).num_rules - 1),
                      prefilter_bucket) != 0) {
            fpsm_free(engine);
            return -1;
        }
    }

    if (rule_reduction_init(&(*engine).reducer, num_rules) != 0) {
        fpsm_free(engine);
        return -1;
    }

    (*engine).initialized = 1;
    return 0;
}

void fpsm_free(fpsm *engine)
{
    if (!engine) {
        return;
    }

    for (uint8_t i = 0; i < (*engine).lens_count; i++) {
        uint32_t len = (*engine).lens[i];
        stage_free(&(*engine).stages[len]);
    }

    rule_reduction_free(&(*engine).reducer);

    memset(engine, 0, sizeof(*engine));
}

size_t fpsm_scan(fpsm *engine, const uint8_t *buf, size_t buf_len,
                 uint32_t *out_rule_ids, size_t max_out)
{
    if (!engine || !(*engine).initialized || !buf || buf_len == 0 || max_out == 0) {
        return 0;
    }

    rule_reduction_clear(&(*engine).reducer);

    const uint8_t *buf_end = buf + buf_len;

    for (uint8_t i = 0; i < (*engine).lens_count; i++) {
        uint32_t len = (*engine).lens[i];

        const uint8_t *p = buf;
        while (p < buf_end) {
            uint8_t bucket_bitmap = 0;
            const uint8_t *match = shiftOrExecBucketWithBitmap(&(*engine).buckets[len],
                                                              p,
                                                              buf_end,
                                                              &bucket_bitmap);
            if (match == buf_end) {
                break;
            }

            if (bucket_bitmap != 0 && match + len <= buf_end) {
                uint64_t key = hash_fnv1a64(match, len);
                uint64_t rule_mask = 0;

                if (stage_get(&(*engine).stages[len], key, bucket_bitmap, &rule_mask)) {
                    while (rule_mask != 0) {
                        uint32_t slot = (uint32_t)__builtin_ctzll(rule_mask);
                        rule_mask &= (rule_mask - 1);
                        if (slot < (*engine).num_rules &&
                            (*engine).rules[slot].prefilter_len == len &&
                            (bucket_bitmap & (1U << (*engine).rules[slot].prefilter_bucket)) != 0) {
                            if (match + (*engine).rules[slot].len <= buf_end &&
                                memcmp(match,
                                       (*engine).rules[slot].pattern,
                                       (*engine).rules[slot].len) == 0) {
                                rule_reduction_set(&(*engine).reducer, slot);
                            }
                        }
                    }
                }
            }

            p = match + 1;
        }
    }

    uint32_t slots[FPSM_MAX_RULES];
    size_t num_slots = rule_reduction_compact(&(*engine).reducer,
                                              slots,
                                              FPSM_MAX_RULES);

    size_t out_n = 0;
    for (size_t i = 0; i < num_slots && out_n < max_out; i++) {
        uint32_t rid = (*engine).rules[slots[i]].rule_id;
        id_array_append_unique(out_rule_ids, &out_n, max_out, rid);
    }

    return out_n;
}
