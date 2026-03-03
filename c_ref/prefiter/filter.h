#ifndef FILTER_H
#define FILTER_H

#include "fpsm/fpsm.h"
#include "header_matcher.h"
#include "nfpsm.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    fpsm fpsm;
    header_matcher header;
    uint32_t fpsm_candidates[HM_MAX_RULES];
    uint32_t header_candidates[HM_MAX_RULES];
    nfpsm nfpsm;
    int nfpsm_enabled;
    int initialized;
} filter;

int filter_init(filter *engine,
                const fpsm_rule *fpsm_rules,
                size_t num_fpsm_rules,
                const hm_port_group *port_groups,
                size_t num_port_groups,
                const hm_rule_binding *bindings,
                size_t num_bindings);

void filter_free(filter *engine);

int filter_enable_nfpsm(filter *engine,
                        const nfpsm_rule *nfpsm_rules,
                        size_t num_nfpsm_rules);

size_t filter_scan(filter *engine,
                   const hm_packet_meta *pkt,
                   const uint8_t *payload,
                   size_t payload_len,
                   uint32_t *out_rule_ids,
                   size_t max_out);

#endif
