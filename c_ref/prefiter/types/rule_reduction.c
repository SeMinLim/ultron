#include "rule_reduction.h"
#include <stdlib.h>
#include <string.h>

int rule_reduction_init(rule_reduction_t *rr, size_t bit_capacity)
{
    if (!rr || bit_capacity == 0) {
        return -1;
    }

    (*rr).bit_capacity = bit_capacity;
    (*rr).word_count = (bit_capacity + 63U) / 64U;
    (*rr).bits = calloc((*rr).word_count, sizeof(uint64_t));
    if (!(*rr).bits) {
        (*rr).bit_capacity = 0;
        (*rr).word_count = 0;
        return -1;
    }
    return 0;
}

void rule_reduction_free(rule_reduction_t *rr)
{
    if (!rr) {
        return;
    }
    free((*rr).bits);
    (*rr).bits = NULL;
    (*rr).bit_capacity = 0;
    (*rr).word_count = 0;
}

void rule_reduction_clear(rule_reduction_t *rr)
{
    if (!rr || !(*rr).bits) {
        return;
    }
    memset((*rr).bits, 0, (*rr).word_count * sizeof(uint64_t));
}

void rule_reduction_set(rule_reduction_t *rr, uint32_t id)
{
    if (!rr || !(*rr).bits || id >= (*rr).bit_capacity) {
        return;
    }
    size_t word_idx = id / 64;
    size_t bit_idx = id % 64;
    (*rr).bits[word_idx] |= 1ULL << bit_idx;
}

static uint32_t pop_lowest_bit(uint64_t *word)
{
    uint64_t value = *word;
#if defined(__GNUC__) || defined(__clang__)
    uint32_t bit = (uint32_t)__builtin_ctzll(value);
#else
    uint32_t bit = 0;
    while ((value & 1U) == 0U) {
        bit++;
        value >>= 1;
    }
#endif
    *word = value & (value - 1U);
    return bit;
}

size_t rule_reduction_compact(const rule_reduction_t *rr,
                              uint32_t *out_ids, size_t max_out)
{
    if (!rr || !(*rr).bits || !out_ids || max_out == 0) {
        return 0;
    }

    size_t count = 0;
    for (size_t word_index = 0; word_index < (*rr).word_count && count < max_out; word_index++) {
        uint64_t word = (*rr).bits[word_index];
        while (word != 0 && count < max_out) {
            uint32_t bit = pop_lowest_bit(&word);
            out_ids[count++] = (uint32_t)(word_index * 64U + bit);
        }
    }
    return count;
}

