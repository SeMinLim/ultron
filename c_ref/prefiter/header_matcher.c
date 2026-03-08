#include "header_matcher.h"
#include "types/id_array.h"
#include <string.h>

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

        id_array_append_unique(out_rule_ids, &out_n, max_out, rid);
    }

    return out_n;
}
