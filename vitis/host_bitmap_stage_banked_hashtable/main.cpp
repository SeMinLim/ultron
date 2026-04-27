#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "xrt/xrt_bo.h"
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"

struct PcapPkt {
    std::vector<uint8_t> data;
};

static std::vector<PcapPkt> load_pcap(const char *path)
{
    std::vector<PcapPkt> pkts;
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return pkts; }

    uint32_t magic; fread(&magic, 4, 1, f);
    bool swapped = (magic == 0xD4C3B2A1);
    fseek(f, 24, SEEK_SET);  

    auto rd32 = [&]() -> uint32_t {
        uint32_t v; fread(&v, 4, 1, f);
        if (swapped) v = __builtin_bswap32(v);
        return v;
    };

    while (!feof(f)) {
        uint32_t ts_sec  = rd32(); (void)ts_sec;
        uint32_t ts_usec = rd32(); (void)ts_usec;
        uint32_t incl    = rd32();
        uint32_t orig    = rd32(); (void)orig;
        if (feof(f) || incl == 0 || incl > 65535) break;
        PcapPkt p;
        p.data.resize(incl);
        if (fread(p.data.data(), 1, incl, f) != incl) break;
        pkts.push_back(std::move(p));
    }
    fclose(f);
    return pkts;
}

// Per-packet parsed metadata. Mirrors the 32B descriptor layout consumed by
// PacketReader.bsv::unpackDesc — the host MUST emit this layout; the kernel
// no longer parses headers itself.
struct PktParsed {
    uint32_t payload_off;   // offset (within blob) of payload byte 0, 64B-aligned
    uint32_t payload_len;   // payload bytes (everything after the L4 header)
    uint8_t  ip_proto;      // IPv4 protocol byte, 0 if not IPv4
    uint8_t  flags;         // bit0=isIpv4, bit1=hasTcp, bit2=hasUdp, bit3=hasIcmp
    uint16_t src_port;      // host byte order (TCP/UDP only)
    uint16_t dst_port;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    std::vector<uint8_t> payload;
};

static uint16_t rd16_be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

// Strip Ethernet (+ optional 802.1Q VLAN) + IPv4 + L4 header. On any parse
// miss, fall back to the whole packet as payload with all-zero meta — the
// kernel will still process the bytes, just without port-offset matching.
static PktParsed parse_packet(const std::vector<uint8_t> &raw)
{
    PktParsed o = {};
    const uint8_t *p   = raw.data();
    size_t        rem = raw.size();
    size_t        cur = 0;

    auto fail_whole = [&]() {
        o.payload.assign(raw.begin(), raw.end());
        o.payload_len = (uint32_t)raw.size();
        return o;
    };

    if (rem < 14) return fail_whole();
    uint16_t etype = rd16_be(p + 12);
    cur = 14;
    while (etype == 0x8100 && cur + 4 <= rem) {  // 802.1Q VLAN tag
        etype = rd16_be(p + cur + 2);
        cur += 4;
    }
    if (etype != 0x0800) return fail_whole();    // not IPv4

    if (cur + 20 > rem) return fail_whole();
    const uint8_t *ip = p + cur;
    if ((ip[0] >> 4) != 4) return fail_whole();
    size_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || cur + ihl > rem) return fail_whole();
    o.ip_proto = ip[9];
    o.flags    = 0x01;                           // isIpv4
    cur += ihl;

    size_t l4_off = cur;
    if (o.ip_proto == 6 /* TCP */) {
        if (l4_off + 20 > rem) return fail_whole();
        const uint8_t *tcp = p + l4_off;
        o.src_port = rd16_be(tcp + 0);
        o.dst_port = rd16_be(tcp + 2);
        size_t doff = ((tcp[12] >> 4) & 0xF) * 4;
        if (doff < 20 || l4_off + doff > rem) return fail_whole();
        o.flags |= 0x02;
        cur = l4_off + doff;
    } else if (o.ip_proto == 17 /* UDP */) {
        if (l4_off + 8 > rem) return fail_whole();
        const uint8_t *udp = p + l4_off;
        o.src_port = rd16_be(udp + 0);
        o.dst_port = rd16_be(udp + 2);
        o.flags |= 0x04;
        cur = l4_off + 8;
    } else if (o.ip_proto == 1 /* ICMP */) {
        if (l4_off + 2 > rem) return fail_whole();
        o.icmp_type = p[l4_off + 0];
        o.icmp_code = p[l4_off + 1];
        o.flags |= 0x08;
        // Spec: ngram position 0 = first byte after Type/Code (i.e. Checksum
        // becomes payload[0]).  Do NOT also skip the 2B checksum.
        cur = l4_off + 2;
    } else {
        cur = l4_off;
    }

    o.payload.assign(raw.begin() + cur, raw.end());
    o.payload_len = (uint32_t)o.payload.size();
    return o;
}

// packet blob (consumed by PacketReader.bsv):
//   [0..64)              64B header
//   [64..64+N*32)        N descriptors × 32B (PacketReader::unpackDesc layout)
//   [data_off..)         payload bytes per packet, each starting on a 64B line
static std::vector<uint8_t> build_pkt_blob(const std::vector<PcapPkt> &pkts)
{
    uint32_t n = (uint32_t)pkts.size();

    std::vector<PktParsed> parsed;
    parsed.reserve(n);
    for (auto &p : pkts) parsed.push_back(parse_packet(p.data));

    uint32_t desc_end = 64 + n * 32;
    uint32_t data_off = (desc_end + 63) & ~63u;

    uint32_t total = data_off;
    for (auto &p : parsed) {
        total += (uint32_t)p.payload.size();
        total  = (total + 63) & ~63u;
    }

    std::vector<uint8_t> blob(total, 0);

    auto w16 = [&](uint32_t off, uint16_t v) { memcpy(blob.data() + off, &v, 2); };
    auto w32 = [&](uint32_t off, uint32_t v) { memcpy(blob.data() + off, &v, 4); };

    w32(0, 0x504B5442u);
    w32(4, n);
    w32(8, total);

    uint32_t cur_off = data_off;
    for (uint32_t i = 0; i < n; i++) {
        PktParsed &m = parsed[i];
        m.payload_off = cur_off;
        uint32_t db = 64 + i * 32;
        w32(db + 0,  m.payload_off);
        w32(db + 4,  m.payload_len);
        blob[db + 8]  = m.ip_proto;
        blob[db + 9]  = m.flags;
        w16(db + 10, m.src_port);
        w16(db + 12, m.dst_port);
        blob[db + 14] = m.icmp_type;
        blob[db + 15] = m.icmp_code;
        // [db+16 .. db+32) reserved, left zero
        if (m.payload_len) {
            memcpy(blob.data() + cur_off, m.payload.data(), m.payload.size());
            cur_off += (uint32_t)m.payload.size();
            cur_off  = (cur_off + 63) & ~63u;
        }
    }

    return blob;
}

// result:
// [0..128)            summary: 32 x u32 counters
// [128..128+N*4)      per-packet: {matched[1], reserved[15], ruleId[16]}
static void print_results(const uint8_t *res, uint32_t pkt_count)
{
    uint32_t matched, processed, db_cyc, pkt_cyc, total_cyc;
    uint32_t dl_cyc, pr_cyc, pp_cyc, ng_cyc, bm_cyc, gm_cyc, ex_cyc, pom_cyc, rw_cyc;
    uint32_t grams_extracted, bitmap_passed, gram_lookups, gram_hits;
    uint32_t exact_checks, exact_hits, exact_misses, pom_checks, pom_hits, pom_misses, no_match_pkts;
    uint32_t stage2_checked, stage2_passed;
    memcpy(&matched,   res +  0, 4);
    memcpy(&processed, res +  4, 4);
    memcpy(&db_cyc,    res +  8, 4);
    memcpy(&pkt_cyc,   res + 12, 4);
    memcpy(&total_cyc, res + 16, 4);
    memcpy(&dl_cyc,    res + 20, 4);
    memcpy(&pr_cyc,    res + 24, 4);
    memcpy(&pp_cyc,    res + 28, 4);
    memcpy(&ng_cyc,    res + 32, 4);
    memcpy(&bm_cyc,    res + 36, 4);
    memcpy(&gm_cyc,    res + 40, 4);
    memcpy(&ex_cyc,    res + 44, 4);
    memcpy(&pom_cyc,   res + 48, 4);
    memcpy(&rw_cyc,    res + 52, 4);
    memcpy(&grams_extracted, res + 56, 4);
    memcpy(&bitmap_passed,   res + 60, 4);
    memcpy(&gram_lookups,    res + 64, 4);
    memcpy(&gram_hits,       res + 68, 4);
    memcpy(&exact_checks,    res + 72, 4);
    memcpy(&exact_hits,      res + 76, 4);
    memcpy(&exact_misses,    res + 80, 4);
    memcpy(&pom_checks,      res + 84, 4);
    memcpy(&pom_hits,        res + 88, 4);
    memcpy(&pom_misses,      res + 92, 4);
    memcpy(&no_match_pkts,   res + 96, 4);
    memcpy(&stage2_checked,  res + 100, 4);
    memcpy(&stage2_passed,   res + 104, 4);
    printf("matched=%u  processed=%u\n", matched, processed);
    printf("cycles: db_load=%u  pkt_proc=%u  total=%u\n",
           db_cyc, pkt_cyc, total_cyc);
    printf("module_cycles: data_loader=%u  pkt_reader=%u  payload_feed=%u  ngram=%u  bitmap=%u  gram=%u  exact=%u  pom=%u  result_writer=%u\n",
           dl_cyc, pr_cyc, pp_cyc, ng_cyc, bm_cyc, gm_cyc, ex_cyc, pom_cyc, rw_cyc);
    // Per-stage gram filter — same shape as c_ref/mky_backup main.c so
    // numbers can be diffed line-for-line against the C reference.
    //
    //   bitmap0   total=every extracted gram, hit=anchors in singleton bm
    //   bitmap1   total=bm0 hits (sequential), hit=anchors whose anchor+3
    //                                          gram is in next-gram bm
    //   hashtable total=bm0 hits, hit=anchors found in cuckoo (post-fix
    //                                 bm0 holds only singletons → 100%)
    //   exact     total=anchors that reached exact match after the per-rule
    //                  stage-viable gate dropped stage-2 rules with bm1 miss
    //   pom       total=exact hits that reached port/offset matching
    auto pct = [](uint32_t hit, uint32_t total) {
        return total ? 100.0 * (double)hit / (double)total : 0.0;
    };
    auto row = [&](const char *name, uint32_t hit, uint32_t total) {
        printf("  %-10s  %10u  %10u  %10u  %7.2f%%\n",
               name, total, hit, total - hit, pct(hit, total));
    };
    printf("=== per-stage gram filter ===\n");
    printf("  %-10s  %10s  %10s  %10s  %8s\n",
           "stage", "total", "hit", "miss", "pass%");
    row("bitmap0",   bitmap_passed, grams_extracted);
    row("bitmap1",   stage2_passed, stage2_checked);
    row("hashtable", gram_hits,     gram_lookups);
    row("exact",     exact_hits,    exact_checks);
    row("pom",       pom_hits,      pom_checks);
    printf("no_match_pkts=%u\n", no_match_pkts);

    for (uint32_t i = 0; i < pkt_count; i++) {
        uint32_t entry;
        memcpy(&entry, res + 128 + i * 4, 4);
        bool hit = (entry >> 31) & 1;
        uint16_t rule_id = entry & 0xFFFF;
        printf("  pkt[%u]: %s  ruleId=%u\n", i, hit ? "MATCH" : "miss", rule_id);
    }
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <xclbin> <db_blob.bin> <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *xclbin_path = argv[1];
    const char *db_path     = argv[2];
    const char *pcap_path   = argv[3];

    std::ifstream db_f(db_path, std::ios::binary | std::ios::ate);
    if (!db_f) { fprintf(stderr, "cannot open %s\n", db_path); return EXIT_FAILURE; }
    size_t db_size = db_f.tellg();
    db_f.seekg(0);
    std::vector<uint8_t> db_blob(db_size);
    db_f.read((char *)db_blob.data(), (std::streamsize)db_size);
    printf("db blob: %zu bytes\n", db_size);

    auto pkts = load_pcap(pcap_path);
    if (pkts.empty()) { fprintf(stderr, "no packets in %s\n", pcap_path); return EXIT_FAILURE; }
    printf("packets: %zu\n", pkts.size());

    auto pkt_blob = build_pkt_blob(pkts);
    printf("pkt blob: %zu bytes\n", pkt_blob.size());

    uint32_t pkt_count = (uint32_t)pkts.size();
    uint32_t db_bytes  = (uint32_t)db_size;

    size_t res_size = 128 + ((pkt_count * 4 + 63) & ~63u);

    xrt::device device{0u};
    xrt::uuid   uuid = device.load_xclbin(xclbin_path);
    auto krnl = xrt::kernel(device, uuid, "kernel:{kernel_1}");

    auto boDb  = xrt::bo(device, db_size,           krnl.group_id(2));
    auto boPkt = xrt::bo(device, pkt_blob.size(),   krnl.group_id(3));
    auto boRes = xrt::bo(device, res_size,           krnl.group_id(4));

    memcpy(boDb.map<uint8_t *>(),  db_blob.data(),   db_size);
    memcpy(boPkt.map<uint8_t *>(), pkt_blob.data(),  pkt_blob.size());
    memset(boRes.map<uint8_t *>(), 0,                res_size);

    boDb.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    boPkt.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    boRes.sync(XCL_BO_SYNC_BO_TO_DEVICE);

    printf("starting kernel...\n");
    auto run = krnl(pkt_count, db_bytes, boDb, boPkt, boRes);
    run.wait();
    printf("kernel done\n");

    boRes.sync(XCL_BO_SYNC_BO_FROM_DEVICE);
    print_results(boRes.map<uint8_t *>(), pkt_count);

    return EXIT_SUCCESS;
}
