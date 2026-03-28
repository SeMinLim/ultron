#include <string.h>
#include "packet_parser.h"

#define ETH_HDR_LEN  14
#define IPV4_MIN_HDR 20

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

int packet_parse(const uint8_t *raw, size_t len, Packet *out)
{
    if (!raw || !out || len < ETH_HDR_LEN + IPV4_MIN_HDR)
        return -1;

    memset(out, 0, sizeof(*out));

    const uint8_t *ip = raw + ETH_HDR_LEN;

    if ((ip[0] >> 4) != 4)
        return -1;

    size_t ip_hdr_len = (ip[0] & 0x0f) * 4;
    if (ip_hdr_len < IPV4_MIN_HDR || len < ETH_HDR_LEN + ip_hdr_len)
        return -1;

    uint16_t ip_total = be16(ip + 2);
    if (len < ETH_HDR_LEN + ip_total)
        return -1;

    out->proto = ip[9];
    const uint8_t *transport = ip + ip_hdr_len;
    size_t transport_len = ip_total - ip_hdr_len;

    switch (out->proto) {
    case PROTO_TCP:
        if (transport_len < 20) return -1;
        out->src_port   = be16(transport);
        out->dst_port   = be16(transport + 2);
        size_t tcp_hdr  = ((transport[12] >> 4) & 0xf) * 4;
        if (tcp_hdr < 20 || transport_len < tcp_hdr) return -1;
        out->payload     = transport + tcp_hdr;
        out->payload_len = transport_len - tcp_hdr;
        break;

    case PROTO_UDP:
        if (transport_len < 8) return -1;
        out->src_port    = be16(transport);
        out->dst_port    = be16(transport + 2);
        out->payload     = transport + 8;
        out->payload_len = transport_len - 8;
        break;

    case PROTO_ICMP:
        if (transport_len < 8) return -1;
        out->icmp_type   = transport[0];
        out->icmp_code   = transport[1];
        out->payload     = transport + 8;
        out->payload_len = transport_len - 8;
        break;

    default:
        return -1;
    }

    return 0;
}
