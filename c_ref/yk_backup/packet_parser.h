#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stddef.h>

#define PROTO_TCP  6
#define PROTO_UDP  17
#define PROTO_ICMP 1

typedef struct {
    uint8_t  proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    const uint8_t *payload;
    size_t         payload_len;
} Packet;

int packet_parse(const uint8_t *raw, size_t len, Packet *out);

#endif
