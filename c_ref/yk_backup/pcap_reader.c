#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap_reader.h"

#define PCAP_MAGIC_LE  0xa1b2c3d4u
#define PCAP_MAGIC_BE  0xd4c3b2a1u

static uint32_t swap32(uint32_t x)
{
    return ((x & 0xff000000u) >> 24)
         | ((x & 0x00ff0000u) >>  8)
         | ((x & 0x0000ff00u) <<  8)
         | ((x & 0x000000ffu) << 24);
}


PcapReader *pcap_open(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    uint32_t magic;
    if (fread(&magic, 4, 1, fp) != 1) { fclose(fp); return NULL; }

    int swapped = 0;
    if      (magic == PCAP_MAGIC_LE) swapped = 0;
    else if (magic == PCAP_MAGIC_BE) swapped = 1;
    else { fclose(fp); return NULL; }

    uint8_t rest[20];
    if (fread(rest, 20, 1, fp) != 1) { fclose(fp); return NULL; }

    uint32_t link_type;
    memcpy(&link_type, rest + 16, 4);
    if (swapped) link_type = swap32(link_type);

    PcapReader *r = malloc(sizeof *r);
    r->fp        = fp;
    r->link_type = link_type;
    r->swapped   = swapped;
    return r;
}

int pcap_next(PcapReader *r, PcapFrame *frame)
{
    uint32_t hdr[4];
    if (fread(hdr, 4, 4, r->fp) != 4) return 0;

    uint32_t ts_sec  = r->swapped ? swap32(hdr[0]) : hdr[0];
    uint32_t ts_usec = r->swapped ? swap32(hdr[1]) : hdr[1];
    uint32_t caplen  = r->swapped ? swap32(hdr[2]) : hdr[2];
    uint32_t origlen = r->swapped ? swap32(hdr[3]) : hdr[3];

    if (caplen > 262144) return 0;

    uint8_t *data = malloc(caplen);
    if (!data) return 0;
    if (fread(data, 1, caplen, r->fp) != caplen) { free(data); return 0; }

    frame->data    = data;
    frame->caplen  = caplen;
    frame->origlen = origlen;
    frame->ts_sec  = ts_sec;
    frame->ts_usec = ts_usec;
    return 1;
}

void pcap_close(PcapReader *r)
{
    if (!r) return;
    fclose(r->fp);
    free(r);
}

void pcap_frame_free(PcapFrame *frame)
{
    free(frame->data);
    frame->data = NULL;
}
