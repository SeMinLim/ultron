#include "filter.h"
#include <string.h>

int filter_init(filter *engine,
                const fpsm_rule *fpsm_rules,
                size_t num_fpsm_rules,
                const hm_port_group *port_groups,
                size_t num_port_groups,
                const hm_rule_binding *bindings,
                size_t num_bindings)
{
    if (!engine || !fpsm_rules || !port_groups || !bindings ||
        num_fpsm_rules == 0 || num_port_groups == 0 || num_bindings == 0) {
        return -1;
    }

    memset(engine, 0, sizeof(*engine));

    if (fpsm_init(&(*engine).fpsm, fpsm_rules, num_fpsm_rules) != 0) {
        return -1;
    }

    if (header_matcher_init(&(*engine).header,
                            port_groups,
                            num_port_groups,
                            bindings,
                            num_bindings) != 0) {
        fpsm_free(&(*engine).fpsm);
        return -1;
    }

    (*engine).initialized = 1;
    return 0;
}

void filter_free(filter *engine)
{
    if (!engine) {
        return;
    }

    fpsm_free(&(*engine).fpsm);
    header_matcher_free(&(*engine).header);
    if ((*engine).nfpsm_enabled) {
        nfpsm_free(&(*engine).nfpsm);
    }
    memset(engine, 0, sizeof(*engine));
}

int filter_enable_nfpsm(filter *engine,
                        const nfpsm_rule *nfpsm_rules,
                        size_t num_nfpsm_rules)
{
    if (!engine || !(*engine).initialized || !nfpsm_rules || num_nfpsm_rules == 0) {
        return -1;
    }

    if ((*engine).nfpsm_enabled) {
        nfpsm_free(&(*engine).nfpsm);
        (*engine).nfpsm_enabled = 0;
    }

    if (nfpsm_init(&(*engine).nfpsm, nfpsm_rules, num_nfpsm_rules) != 0) {
        return -1;
    }

    (*engine).nfpsm_enabled = 1;
    return 0;
}

size_t filter_scan(filter *engine,
                   const hm_packet_meta *pkt,
                   const uint8_t *payload,
                   size_t payload_len,
                   uint32_t *out_rule_ids,
                   size_t max_out)
{
    if (!engine || !(*engine).initialized || !pkt || !payload || !out_rule_ids ||
        max_out == 0) {
        return 0;
    }

    size_t num_candidates = fpsm_scan(&(*engine).fpsm,
                                      payload,
                                      payload_len,
                                      (*engine).fpsm_candidates,
                                      HM_MAX_RULES);
    if (num_candidates == 0) {
        return 0;
    }

    size_t num_header = header_matcher_filter(&(*engine).header,
                                              pkt,
                                              (*engine).fpsm_candidates,
                                              num_candidates,
                                              (*engine).header_candidates,
                                              HM_MAX_RULES);
    if (num_header == 0) {
        return 0;
    }

    if (!(*engine).nfpsm_enabled) {
        size_t out_n = (num_header < max_out) ? num_header : max_out;
        memcpy(out_rule_ids, (*engine).header_candidates, out_n * sizeof(uint32_t));
        return out_n;
    }

    return nfpsm_filter(&(*engine).nfpsm,
                        payload,
                        payload_len,
                        (*engine).header_candidates,
                        num_header,
                        out_rule_ids,
                        max_out);
}
