#ifndef RULE_REDUCTION_H
#define RULE_REDUCTION_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t *bits;
    size_t bit_capacity;
    size_t word_count;
} rule_reduction_t;

int rule_reduction_init(rule_reduction_t *rr, size_t bit_capacity);

void rule_reduction_free(rule_reduction_t *rr);

void rule_reduction_clear(rule_reduction_t *rr);

void rule_reduction_set(rule_reduction_t *rr, uint32_t id);

size_t rule_reduction_compact(const rule_reduction_t *rr,
                              uint32_t *out_ids, size_t max_out);

#endif
