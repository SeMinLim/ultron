#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t *data;
    uint32_t caplen;
    uint32_t origlen;
    uint32_t ts_sec;
    uint32_t ts_usec;
} PcapFrame;

typedef struct {
    FILE    *fp;
    uint32_t link_type;
    int      swapped;
} PcapReader;

PcapReader *pcap_open(const char *path);
int         pcap_next(PcapReader *r, PcapFrame *frame);
void        pcap_close(PcapReader *r);
void        pcap_frame_free(PcapFrame *frame);

#endif
