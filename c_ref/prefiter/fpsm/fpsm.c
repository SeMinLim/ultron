#include "fpsm.h"
#include "bucket_shift_or.h"
#include <stdlib.h>
#include <string.h>

static uint64_t fnv1a64(const uint8_t *bytes, size_t len)
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
    size_t p = FPSM_MIN_HASH_CAP;
    while (p < v) {
        p <<= 1U;
    }
    return p;
}

static int stage_init(fpsm_stage *s, size_t cap)
{
    if (!s) {
        return -1;
    }

    memset(s, 0, sizeof(*s));
    if (cuckoo_hash_init(&(*s).filter, cap) != 0) {
        return -1;
    }
    if (cuckoo_hash_init(&(*s).index, cap) != 0) {
        cuckoo_hash_free(&(*s).filter);
        return -1;
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
        cuckoo_hash_free(&(*s).filter);
        cuckoo_hash_free(&(*s).index);
    }

    memset(s, 0, sizeof(*s));
}

static int stage_add(fpsm_stage *s,
                     uint64_t key,
                     uint32_t rule_slot,
                     fpsm_posting *postings,
                     size_t *num_postings,
                     size_t max_postings)
{
    if (!s || !(*s).initialized || !postings || !num_postings ||
        *num_postings >= max_postings) {
        return -1;
    }

    uint64_t head_enc = 0;
    uint32_t head = FPSM_POSTING_NONE;
    if (cuckoo_hash_lookup(&(*s).index, key, &head_enc) && head_enc > 0) {
        head = (uint32_t)(head_enc - 1);
    }

    postings[*num_postings].rule_slot = rule_slot;
    postings[*num_postings].next = head;

    if (cuckoo_hash_insert(&(*s).index, key, (uint64_t)(*num_postings + 1)) != 0) {
        return -1;
    }
    if (cuckoo_hash_insert(&(*s).filter, key, 1) != 0) {
        return -1;
    }

    (*num_postings)++;
    return 0;
}

static int stage_probe(const fpsm_stage *s, uint64_t key, uint32_t *out_head)
{
    if (!s || !(*s).initialized || !out_head) {
        return 0;
    }

    uint64_t present = 0;
    if (!cuckoo_hash_lookup(&(*s).filter, key, &present) || present == 0) {
        return 0;
    }

    uint64_t head_enc = 0;
    if (!cuckoo_hash_lookup(&(*s).index, key, &head_enc) || head_enc == 0) {
        return 0;
    }

    *out_head = (uint32_t)(head_enc - 1);
    return 1;
}

int fpsm_init(fpsm *engine, const fpsm_rule *rules, size_t num_rules)
{
    if (!engine || !rules || num_rules == 0 || num_rules > FPSM_MAX_RULES) {
        return -1;
    }

    memset(engine, 0, sizeof(*engine));

    (*engine).rules = calloc(num_rules, sizeof(*(*engine).rules));
    (*engine).postings = calloc(num_rules, sizeof(*(*engine).postings));
    if (!(*engine).rules || !(*engine).postings) {
        fpsm_free(engine);
        return -1;
    }

    size_t len_counts[FPSM_MAX_PATTERN_LEN + 1];
    const uint8_t *first_pattern[FPSM_MAX_PATTERN_LEN + 1];
    memset(len_counts, 0, sizeof(len_counts));
    memset(first_pattern, 0, sizeof(first_pattern));

    for (size_t i = 0; i < num_rules; i++) {
        if (!rules[i].pattern || rules[i].len == 0 ||
            rules[i].len > FPSM_MAX_PATTERN_LEN ||
            rules[i].len > SHIFT_OR_MAX_PATTERN_LEN) {
            fpsm_free(engine);
            return -1;
        }

        uint32_t len = (uint32_t)rules[i].len;
        len_counts[len]++;
        if (!first_pattern[len]) {
            first_pattern[len] = rules[i].pattern;
        }
    }

    for (uint32_t len = 1; len <= FPSM_MAX_PATTERN_LEN; len++) {
        if (len_counts[len] == 0) {
            continue;
        }

        shiftOrBucketInit(&(*engine).buckets[len], first_pattern[len], len);
        if ((*engine).buckets[len].pattern_len == 0) {
            fpsm_free(engine);
            return -1;
        }

        if (stage_init(&(*engine).stages[len], next_pow2(len_counts[len] * 2U)) != 0) {
            fpsm_free(engine);
            return -1;
        }

        (*engine).used[len] = 1;
        (*engine).lens[(*engine).lens_count++] = (uint8_t)len;
    }

    size_t len_seen[FPSM_MAX_PATTERN_LEN + 1];
    memset(len_seen, 0, sizeof(len_seen));

    for (size_t i = 0; i < num_rules; i++) {
        uint32_t len = (uint32_t)rules[i].len;
        uint64_t key = fnv1a64(rules[i].pattern, rules[i].len);

        if (len_seen[len] > 0) {
            if (shiftOrBucketAddPattern(&(*engine).buckets[len], rules[i].pattern, rules[i].len) != 0) {
                fpsm_free(engine);
                return -1;
            }
        }
        len_seen[len]++;

        (*engine).rules[(*engine).num_rules] = rules[i];

        if (stage_add(&(*engine).stages[len],
                      key,
                      (uint32_t)(*engine).num_rules,
                      (*engine).postings,
                      &(*engine).num_postings,
                      num_rules) != 0) {
            fpsm_free(engine);
            return -1;
        }

        (*engine).num_rules++;
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
    free((*engine).rules);
    free((*engine).postings);

    memset(engine, 0, sizeof(*engine));
}

size_t fpsm_scan(fpsm *engine, const uint8_t *buf, size_t buf_len,
                 uint32_t *out_rule_ids, size_t max_out)
{
    if (!engine || !(*engine).initialized || !buf || !out_rule_ids ||
        buf_len == 0 || max_out == 0) {
        return 0;
    }

    rule_reduction_clear(&(*engine).reducer);

    const uint8_t *buf_end = buf + buf_len;

    for (uint8_t i = 0; i < (*engine).lens_count; i++) {
        uint32_t len = (*engine).lens[i];

        const uint8_t *p = buf;
        while (p < buf_end) {
            const uint8_t *match = shiftOrExecBucket(&(*engine).buckets[len], p, buf_end);
            if (match == buf_end) {
                break;
            }

            if (match + len <= buf_end) {
                uint64_t key = fnv1a64(match, len);
                uint32_t post = FPSM_POSTING_NONE;

                if (stage_probe(&(*engine).stages[len], key, &post)) {
                    while (post != FPSM_POSTING_NONE && post < (*engine).num_postings) {
                        uint32_t slot = (*engine).postings[post].rule_slot;
                        uint32_t next = (*engine).postings[post].next;

                        if (slot < (*engine).num_rules &&
                            (*engine).rules[slot].len == len &&
                            memcmp(match, (*engine).rules[slot].pattern, len) == 0) {
                            rule_reduction_set(&(*engine).reducer, slot);
                        }

                        post = next;
                    }
                }
            }

            p = match + 1;
        }
    }

    uint32_t *slots = malloc((*engine).num_rules * sizeof(*slots));
    if (!slots) {
        return 0;
    }

    size_t num_slots = rule_reduction_compact(&(*engine).reducer,
                                              slots,
                                              (*engine).num_rules);

    size_t out_n = 0;
    for (size_t i = 0; i < num_slots && out_n < max_out; i++) {
        uint32_t rid = (*engine).rules[slots[i]].rule_id;
        append_unique_id(out_rule_ids, &out_n, max_out, rid);
    }

    free(slots);

    return out_n;
}
