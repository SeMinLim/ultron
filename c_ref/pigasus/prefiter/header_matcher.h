#ifndef HEADER_MATCHER_H
#define HEADER_MATCHER_H

#include <stddef.h>
#include <stdint.h>

#define HM_MAX_PORT_GROUPS 512
#define HM_MAX_RULES 1024
#define HM_MAX_PORTS_PER_GROUP 32
#define HM_NO_GROUP UINT16_MAX

typedef enum {
    HM_PORT_GROUP_WILDCARD = 0,
    HM_PORT_GROUP_SINGLE,
    HM_PORT_GROUP_RANGE,
    HM_PORT_GROUP_LIST
} hm_port_group_type;

typedef struct {
    hm_port_group_type type;
    uint16_t single;
    uint16_t range_start;
    uint16_t range_end;
    uint16_t ports[HM_MAX_PORTS_PER_GROUP];
    uint16_t num_ports;
} hm_port_group;

typedef struct {
    uint32_t rule_id;
    uint16_t port_group_id;
} hm_rule_binding;

typedef struct {
    uint8_t ip_proto;
    uint16_t src_port;
    uint16_t dst_port;
} hm_packet_meta;

typedef struct {
    hm_port_group port_groups[HM_MAX_PORT_GROUPS];
    uint16_t num_port_groups;
    uint16_t rule_to_group[HM_MAX_RULES];
    int initialized;
} header_matcher;

int header_matcher_init(header_matcher *matcher,
                        const hm_port_group *groups, size_t num_groups,
                        const hm_rule_binding *bindings, size_t num_bindings);

void header_matcher_free(header_matcher *matcher);

size_t header_matcher_filter(const header_matcher *matcher,
                             const hm_packet_meta *pkt,
                             const uint32_t *candidate_rule_ids,
                             size_t num_candidates,
                             uint32_t *out_rule_ids,
                             size_t max_out);

#endif
