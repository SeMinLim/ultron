#include <string.h>
#include "packet_parser.h"

#define ETH_HDR_LEN   14
#define IPV4_MIN_HDR  20
#define IPV6_HDR_LEN  40

#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_IPV6  0x86DD

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int parse_transport(uint8_t proto,
                            const uint8_t *transport, size_t transport_len,
                            Packet *out)
{
    out->proto = proto;

    switch (proto) {
    case PROTO_TCP:
        if (transport_len < 20) return -1;
        out->src_port        = be16(transport);
        out->dst_port        = be16(transport + 2);
        size_t tcp_hdr       = ((transport[12] >> 4) & 0xf) * 4;
        if (tcp_hdr < 20 || transport_len < tcp_hdr) return -1;
        out->payload         = transport + tcp_hdr;
        out->payload_len     = transport_len - tcp_hdr;
        return 0;

    case PROTO_UDP:
        if (transport_len < 8) return -1;
        out->src_port        = be16(transport);
        out->dst_port        = be16(transport + 2);
        out->payload         = transport + 8;
        out->payload_len     = transport_len - 8;
        return 0;

    case PROTO_ICMP:
    case PROTO_ICMP6:
        if (transport_len < 8) return -1;
        out->icmp_type       = transport[0];
        out->icmp_code       = transport[1];
        out->payload         = transport + 8;
        out->payload_len     = transport_len - 8;
        return 0;

    default:
        return -1;
    }
}

int packet_parse(const uint8_t *raw, size_t len, Packet *out)
{
    if (!raw || !out || len < ETH_HDR_LEN)
        return -1;

    memset(out, 0, sizeof(*out));

    uint16_t ethertype = be16(raw + 12);

    const uint8_t *l3 = raw + ETH_HDR_LEN;
    size_t         l3_len = len - ETH_HDR_LEN;
    if (ethertype == 0x8100 && l3_len >= 4) {
        ethertype = be16(l3 + 2);
        l3    += 4;
        l3_len -= 4;
    }

    if (ethertype == ETHERTYPE_IPV4) {
        if (l3_len < IPV4_MIN_HDR) return -1;
        if ((l3[0] >> 4) != 4)    return -1;

        size_t ip_hdr_len = (l3[0] & 0x0f) * 4;
        if (ip_hdr_len < IPV4_MIN_HDR || l3_len < ip_hdr_len) return -1;

        uint16_t ip_total = be16(l3 + 2);
        if (l3_len < ip_total) return -1;

        uint8_t proto         = l3[9];
        const uint8_t *trans  = l3 + ip_hdr_len;
        size_t  trans_len     = ip_total - ip_hdr_len;

        return parse_transport(proto, trans, trans_len, out);

    } else if (ethertype == ETHERTYPE_IPV6) {
        if (l3_len < IPV6_HDR_LEN) return -1;
        if ((l3[0] >> 4) != 6)    return -1;

        uint16_t payload_len  = be16(l3 + 4);
        uint8_t  next_header  = l3[6];

        if (l3_len < (size_t)(IPV6_HDR_LEN + payload_len)) return -1;

        const uint8_t *trans  = l3 + IPV6_HDR_LEN;
        size_t  trans_len     = payload_len;

        while (next_header != PROTO_TCP  &&
               next_header != PROTO_UDP  &&
               next_header != PROTO_ICMP6) {
            if (next_header == 0   ||
                next_header == 43  ||
                next_header == 60  ||
                next_header == 51  ||
                next_header == 135) {
                if (trans_len < 2) return -1;
                size_t ext_len = ((size_t)trans[1] + 1) * 8;
                if (trans_len < ext_len) return -1;
                next_header = trans[0];
                trans      += ext_len;
                trans_len  -= ext_len;
            } else {
                return -1;
            }
        }

        return parse_transport(next_header, trans, trans_len, out);

    } else {
        return -1;
    }
}
