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

// packet 
//   [0..64)              64B header
//   [64..64+N*16)        N descriptors × 16B {offset:u32, len:u32, reserved:8B}
//   [desc_end_aligned..) raw packet bytes concatenated
static std::vector<uint8_t> build_pkt_blob(const std::vector<PcapPkt> &pkts)
{
    uint32_t n = (uint32_t)pkts.size();
    uint32_t desc_end = 64 + n * 16;
    uint32_t data_off = (desc_end + 63) & ~63u;

    uint32_t total = data_off;
    for (auto &p : pkts) {
        total += (uint32_t)p.data.size();
        total  = (total + 63) & ~63u;
    }

    std::vector<uint8_t> blob(total, 0);

    auto w32 = [&](uint32_t off, uint32_t v) {
        memcpy(blob.data() + off, &v, 4);
    };

    w32(0, 0x504B5442u);
    w32(4, n);
    w32(8, total);

    uint32_t cur_off = data_off;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t desc_base = 64 + i * 16;
        w32(desc_base + 0, cur_off);
        w32(desc_base + 4, (uint32_t)pkts[i].data.size());
        memcpy(blob.data() + cur_off, pkts[i].data.data(), pkts[i].data.size());
        cur_off += (uint32_t)pkts[i].data.size();
        cur_off  = (cur_off + 63) & ~63u;
    }

    return blob;
}

// Result layout:
//   [0..128)            summary: 32 x u32 counters
//   [128..128+N*4)      per-packet: {matched[1], reserved[15], ruleId[16]}
static void print_results(const uint8_t *res, uint32_t pkt_count)
{
    uint32_t matched, processed, db_cyc, pkt_cyc, total_cyc;
    uint32_t dl_cyc, pr_cyc, pp_cyc, ng_cyc, bm_cyc, gm_cyc, ex_cyc, pom_cyc, rw_cyc;
    uint32_t grams_extracted, bitmap_passed, gram_lookups, gram_hits;
    uint32_t exact_checks, exact_hits, exact_misses, port_checks, port_hits, port_misses, no_match_pkts;
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
    memcpy(&port_checks,     res + 84, 4);
    memcpy(&port_hits,       res + 88, 4);
    memcpy(&port_misses,     res + 92, 4);
    memcpy(&no_match_pkts,   res + 96, 4);
    printf("matched=%u  processed=%u\n", matched, processed);
    printf("cycles: db_load=%u  pkt_proc=%u  total=%u\n",
           db_cyc, pkt_cyc, total_cyc);
    printf("module_cycles: data_loader=%u  packet_reader=%u  packet_parser=%u  ngram=%u  bitmap=%u  gram=%u  exact=%u  port=%u  result_writer=%u\n",
           dl_cyc, pr_cyc, pp_cyc, ng_cyc, bm_cyc, gm_cyc, ex_cyc, pom_cyc, rw_cyc);
    printf("stats: grams_extracted=%u  bitmap_passed=%u  gram_lookups=%u  gram_hits=%u  exact_checks=%u  exact_hits=%u  exact_misses=%u  port_checks=%u  port_hits=%u  port_misses=%u  no_match_pkts=%u\n",
           grams_extracted, bitmap_passed, gram_lookups, gram_hits, exact_checks,
           exact_hits, exact_misses, port_checks, port_hits, port_misses, no_match_pkts);

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
