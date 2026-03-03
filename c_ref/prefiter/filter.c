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

#ifdef FILTER_TEST
#include <stdio.h>

int main(void)
{
    filter engine;

    fpsm_rule fpsm_rules[] = {
        { (const uint8_t *)"world", 5, 10 },
        { (const uint8_t *)"hello", 5, 11 },
        { (const uint8_t *)"or", 2, 12 },
    };

    hm_port_group groups[3];
    memset(groups, 0, sizeof(groups));
    groups[0].type = HM_PORT_GROUP_WILDCARD;
    groups[1].type = HM_PORT_GROUP_SINGLE;
    groups[1].single = 80;
    groups[2].type = HM_PORT_GROUP_RANGE;
    groups[2].range_start = 1000;
    groups[2].range_end = 2000;

    hm_rule_binding bindings[] = {
        { 10, 0 },
        { 11, 1 },
        { 12, 2 },
    };

    nfpsm_rule nf_rules[3];
    memset(nf_rules, 0, sizeof(nf_rules));
    nf_rules[0].rule_id = 10;
    nf_rules[0].strings[0] = (const uint8_t *)"world";
    nf_rules[0].lens[0] = 5;
    nf_rules[0].num_strings = 1;

    nf_rules[1].rule_id = 11;
    nf_rules[1].strings[0] = (const uint8_t *)"hello";
    nf_rules[1].lens[0] = 5;
    nf_rules[1].num_strings = 1;

    nf_rules[2].rule_id = 12;
    nf_rules[2].strings[0] = (const uint8_t *)"or";
    nf_rules[2].lens[0] = 2;
    nf_rules[2].num_strings = 1;

    if (filter_init(&engine,
                    fpsm_rules,
                    3,
                    groups,
                    3,
                    bindings,
                    3) != 0) {
        fprintf(stderr, "filter: init failed\n");
        return 1;
    }

    if (filter_enable_nfpsm(&engine, nf_rules, 3) != 0) {
        fprintf(stderr, "filter: nfpsm enable failed\n");
        filter_free(&engine);
        return 1;
    }

    {
        const uint8_t *payload = (const uint8_t *)"hello world";
        hm_packet_meta pkt = { 6, 50000, 80 };
        uint32_t out[8];
        size_t n = filter_scan(&engine, &pkt, payload, 11, out, 8);
        if (n != 2 || out[0] != 10 || out[1] != 11) {
            fprintf(stderr, "filter: case 1 failed (n=%zu)\n", n);
            filter_free(&engine);
            return 1;
        }
    }

    {
        const uint8_t *payload = (const uint8_t *)"hello world";
        hm_packet_meta pkt = { 6, 1500, 22 };
        uint32_t out[8];
        size_t n = filter_scan(&engine, &pkt, payload, 11, out, 8);
        if (n != 2 || out[0] != 10 || out[1] != 12) {
            fprintf(stderr, "filter: case 2 failed (n=%zu)\n", n);
            filter_free(&engine);
            return 1;
        }
    }

    {
        const uint8_t *payload = (const uint8_t *)"xxxxxxxxxx";
        hm_packet_meta pkt = { 6, 50000, 80 };
        uint32_t out[8];
        size_t n = filter_scan(&engine, &pkt, payload, 10, out, 8);
        if (n != 0) {
            fprintf(stderr, "filter: case 3 failed (n=%zu)\n", n);
            filter_free(&engine);
            return 1;
        }
    }

    filter_free(&engine);
    printf("filter: all tests passed\n");
    return 0;
}
#endif
