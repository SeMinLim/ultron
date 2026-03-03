#include "header_matcher.h"
#include <string.h>

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

static int valid_group(const hm_port_group *group)
{
    switch ((*group).type) {
    case HM_PORT_GROUP_WILDCARD:
        return 1;
    case HM_PORT_GROUP_SINGLE:
        return 1;
    case HM_PORT_GROUP_RANGE:
        return (*group).range_start <= (*group).range_end;
    case HM_PORT_GROUP_LIST:
        return (*group).num_ports > 0 && (*group).num_ports <= HM_MAX_PORTS_PER_GROUP;
    default:
        return 0;
    }
}

static int port_in_group(const hm_port_group *group, uint16_t port)
{
    switch ((*group).type) {
    case HM_PORT_GROUP_WILDCARD:
        return 1;
    case HM_PORT_GROUP_SINGLE:
        return port == (*group).single;
    case HM_PORT_GROUP_RANGE:
        return port >= (*group).range_start && port <= (*group).range_end;
    case HM_PORT_GROUP_LIST:
        for (uint16_t i = 0; i < (*group).num_ports; i++) {
            if ((*group).ports[i] == port) {
                return 1;
            }
        }
        return 0;
    default:
        return 0;
    }
}

int header_matcher_init(header_matcher *matcher,
                        const hm_port_group *groups, size_t num_groups,
                        const hm_rule_binding *bindings, size_t num_bindings)
{
    if (!matcher || !groups || !bindings || num_groups == 0 || num_bindings == 0 ||
        num_groups > HM_MAX_PORT_GROUPS) {
        return -1;
    }

    memset(matcher, 0, sizeof(*matcher));
    for (size_t i = 0; i < HM_MAX_RULES; i++) {
        (*matcher).rule_to_group[i] = HM_NO_GROUP;
    }

    for (size_t i = 0; i < num_groups; i++) {
        if (!valid_group(&groups[i])) {
            return -1;
        }
        (*matcher).port_groups[i] = groups[i];
    }
    (*matcher).num_port_groups = (uint16_t)num_groups;

    for (size_t i = 0; i < num_bindings; i++) {
        if (bindings[i].rule_id >= HM_MAX_RULES ||
            bindings[i].port_group_id >= (*matcher).num_port_groups) {
            return -1;
        }
        (*matcher).rule_to_group[bindings[i].rule_id] = bindings[i].port_group_id;
    }

    (*matcher).initialized = 1;
    return 0;
}

void header_matcher_free(header_matcher *matcher)
{
    if (!matcher) {
        return;
    }
    memset(matcher, 0, sizeof(*matcher));
}

size_t header_matcher_filter(const header_matcher *matcher,
                             const hm_packet_meta *pkt,
                             const uint32_t *candidate_rule_ids,
                             size_t num_candidates,
                             uint32_t *out_rule_ids,
                             size_t max_out)
{
    if (!matcher || !(*matcher).initialized || !pkt || !candidate_rule_ids || !out_rule_ids ||
        max_out == 0) {
        return 0;
    }

    size_t out_n = 0;
    for (size_t i = 0; i < num_candidates && out_n < max_out; i++) {
        uint32_t rid = candidate_rule_ids[i];
        if (rid >= HM_MAX_RULES) {
            continue;
        }

        uint16_t gid = (*matcher).rule_to_group[rid];
        if (gid == HM_NO_GROUP || gid >= (*matcher).num_port_groups) {
            continue;
        }

        const hm_port_group *group = &(*matcher).port_groups[gid];
        int matched = port_in_group(group, (*pkt).dst_port) ||
                      port_in_group(group, (*pkt).src_port);
        if (!matched) {
            continue;
        }

        append_unique_id(out_rule_ids, &out_n, max_out, rid);
    }

    return out_n;
}

#ifdef HEADER_MATCHER_TEST
#include <stdio.h>

int main(void)
{
    header_matcher matcher;
    hm_port_group groups[4];
    hm_rule_binding bindings[4];
    hm_packet_meta pkt;
    uint32_t candidates[6];
    uint32_t out[8];
    size_t n;

    memset(groups, 0, sizeof(groups));

    groups[0].type = HM_PORT_GROUP_WILDCARD;

    groups[1].type = HM_PORT_GROUP_SINGLE;
    groups[1].single = 80;

    groups[2].type = HM_PORT_GROUP_RANGE;
    groups[2].range_start = 1000;
    groups[2].range_end = 2000;

    groups[3].type = HM_PORT_GROUP_LIST;
    groups[3].ports[0] = 53;
    groups[3].ports[1] = 443;
    groups[3].num_ports = 2;

    bindings[0].rule_id = 10;
    bindings[0].port_group_id = 0;
    bindings[1].rule_id = 11;
    bindings[1].port_group_id = 1;
    bindings[2].rule_id = 12;
    bindings[2].port_group_id = 2;
    bindings[3].rule_id = 13;
    bindings[3].port_group_id = 3;

    if (header_matcher_init(&matcher, groups, 4, bindings, 4) != 0) {
        fprintf(stderr, "header_matcher: init failed\n");
        return 1;
    }

    candidates[0] = 10;
    candidates[1] = 11;
    candidates[2] = 12;
    candidates[3] = 13;
    candidates[4] = 10;
    candidates[5] = 9999;

    pkt.ip_proto = 6;
    pkt.src_port = 50000;
    pkt.dst_port = 80;
    n = header_matcher_filter(&matcher, &pkt, candidates, 6, out, 8);
    if (n != 2 || out[0] != 10 || out[1] != 11) {
        fprintf(stderr, "header_matcher: case 1 failed (n=%zu)\n", n);
        return 1;
    }

    pkt.src_port = 1500;
    pkt.dst_port = 22;
    n = header_matcher_filter(&matcher, &pkt, candidates, 6, out, 8);
    if (n != 2 || out[0] != 10 || out[1] != 12) {
        fprintf(stderr, "header_matcher: case 2 failed (n=%zu)\n", n);
        return 1;
    }

    pkt.src_port = 12345;
    pkt.dst_port = 443;
    n = header_matcher_filter(&matcher, &pkt, candidates, 6, out, 1);
    if (n != 1 || out[0] != 10) {
        fprintf(stderr, "header_matcher: max_out failed (n=%zu)\n", n);
        return 1;
    }

    header_matcher_free(&matcher);
    printf("header_matcher: all tests passed\n");
    return 0;
}
#endif
