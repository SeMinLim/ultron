#include <string.h>
#include "packet_parser.h"

// Reference packet parser.  Mirrors parse_packet() in the host program
// (sw/host_nicxion_rev2_ipv6/main.cpp), which defines what the kernel is fed:
//
//   - Ethernet, 802.1Q tags including 802.1ad / legacy QinQ outer tags
//   - IPv4 (options), IPv6 (extension headers 0/43/60 and fragment 44)
//   - the datagram ends at the IP length (IPv4 total length, IPv6 payload
//     length), so Ethernet padding is not payload; IPv4 total length 0 (a
//     capture taken before segmentation offload) keeps the frame length, and
//     a length running past the captured bytes is clamped
//   - non-first fragments (IPv4 or IPv6) have no L4 header: ports 0, all of
//     the fragment data is payload
//   - TCP/UDP: ports, payload after the header; ICMP (1) and ICMPv6 (58):
//     type/code, payload right after them
//   - any other protocol (AH 51, ESP 50, GRE 47, SCTP 132, ...) keeps its L4
//     bytes as payload; AH/ESP are the protocol in IPv6 too, as in IPv4
//
// Returns -1 where the host falls back to "whole frame, protocol 0" (not IP,
// malformed or truncated headers).  No rule has protocol 0, so skipping those
// frames changes no match.

#define ETH_HDR_LEN   14
#define IPV4_MIN_HDR  20
#define IPV6_HDR_LEN  40

#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_IPV6  0x86DD

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

int packet_parse(const uint8_t *raw, size_t len, Packet *out)
{
    if (!raw || !out || len < ETH_HDR_LEN)
        return -1;
    memset(out, 0, sizeof(*out));

    size_t   rem = len;
    size_t   cur = ETH_HDR_LEN;
    uint16_t ethertype = be16(raw + 12);
    while ((ethertype == 0x8100 || ethertype == 0x88A8 || ethertype == 0x9100) && cur + 4 <= rem) {
        ethertype = be16(raw + cur + 2);
        cur += 4;
    }

    int l4_present = 1;
    if (ethertype == ETHERTYPE_IPV4) {
        if (cur + IPV4_MIN_HDR > rem) return -1;
        const uint8_t *ip = raw + cur;
        if ((ip[0] >> 4) != 4) return -1;
        size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
        if (ihl < IPV4_MIN_HDR || cur + ihl > rem) return -1;
        size_t tot = be16(ip + 2);
        if (tot != 0) {
            if (tot < ihl) return -1;
            if (cur + tot < rem) rem = cur + tot;
        }
        out->proto = ip[9];
        if ((be16(ip + 6) & 0x1FFF) != 0) l4_present = 0;
        cur += ihl;
    } else if (ethertype == ETHERTYPE_IPV6) {
        if (cur + IPV6_HDR_LEN > rem) return -1;
        const uint8_t *ip = raw + cur;
        if ((ip[0] >> 4) != 6) return -1;
        uint16_t plen = be16(ip + 4);
        if (plen != 0 && cur + IPV6_HDR_LEN + plen < rem) rem = cur + IPV6_HDR_LEN + plen;
        uint8_t nh = ip[6];
        cur += IPV6_HDR_LEN;
        for (int hops = 0; hops < 8; hops++) {
            if (nh == 0 || nh == 43 || nh == 60) {
                if (cur + 8 > rem) return -1;
                size_t ext = ((size_t)raw[cur + 1] + 1) * 8;
                if (cur + ext > rem) return -1;
                nh = raw[cur];
                cur += ext;
            } else if (nh == 44) {
                if (cur + 8 > rem) return -1;
                uint16_t off = be16(raw + cur + 2) >> 3;
                nh = raw[cur];
                cur += 8;
                if (off != 0) { l4_present = 0; break; }
            } else {
                break;
            }
        }
        out->proto = nh;
    } else {
        return -1;
    }

    size_t l4 = cur;
    if (l4_present) {
        switch (out->proto) {
        case PROTO_TCP: {
            if (l4 + 20 > rem) return -1;
            out->src_port = be16(raw + l4);
            out->dst_port = be16(raw + l4 + 2);
            size_t doff = (size_t)((raw[l4 + 12] >> 4) & 0xf) * 4;
            if (doff < 20 || l4 + doff > rem) return -1;
            cur = l4 + doff;
            break;
        }
        case PROTO_UDP:
            if (l4 + 8 > rem) return -1;
            out->src_port = be16(raw + l4);
            out->dst_port = be16(raw + l4 + 2);
            cur = l4 + 8;
            break;
        case PROTO_ICMP:
        case PROTO_ICMP6:
            if (l4 + 2 > rem) return -1;
            out->icmp_type = raw[l4];
            out->icmp_code = raw[l4 + 1];
            cur = l4 + 2;
            break;
        default:
            break;
        }
    }

    out->payload     = raw + cur;
    out->payload_len = rem - cur;
    return 0;
}
