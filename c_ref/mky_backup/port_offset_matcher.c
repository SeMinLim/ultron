#include "port_offset_matcher.h"

static const Rule *find_rule(const RuleSet *rs, int rule_id)
{
    for (int i = 0; i < rs->count; i++)
        if (rs->rules[i].id == rule_id)
            return &rs->rules[i];
    return NULL;
}

static int group_match(const Rule *r, const Packet *pkt)
{
    if (pkt->proto != r->proto)
        return 0;

    switch (r->proto) {
    case 6:
        if (r->is_request == 1)
            return pkt->dst_port == r->port;
        else
            return pkt->src_port == r->port;

    case 17:
        if (r->is_request == 1)
            return pkt->dst_port == r->port;
        else
            return pkt->src_port == r->port;

    case 1:
    case 58:
        return pkt->icmp_type == r->icmp_type
            && pkt->icmp_code == r->icmp_code;

    default:
        return 1;
    }
}

int port_offset_match(const MatchResult *matches, int nm,
                      const RuleSet *rs,
                      const Packet *pkt,
                      MatchResult *out, int out_max)
{
    int n = 0;

    for (int i = 0; i < nm; i++) {
        const Rule *r = find_rule(rs, matches[i].rule_id);
        if (!r) continue;

        if (!group_match(r, pkt))
            continue;

        int start    = matches[i].match_start;
        int pay_len  = (int)pkt->payload_len;

        switch (r->offset_mode) {
        case 1: {
            int end = (pay_len < r->offset_val) ? pay_len : r->offset_val;
            if (start > end) continue;
            break;
        }
        case 2:
            if (start < r->offset_val) continue;
            break;
        case 3:
            if (start != r->offset_val) continue;
            break;
        default:
            break;
        }

        if (n < out_max)
            out[n] = matches[i];
        n++;
    }

    return n;
}
