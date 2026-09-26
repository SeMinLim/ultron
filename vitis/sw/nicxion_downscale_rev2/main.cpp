#include <cstdint>
#include <chrono>
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

struct PktParsed {
    uint32_t payload_off;
    uint32_t payload_len;
    uint8_t  ip_proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint32_t src_ip;        // network byte order, store-only
    uint32_t dst_ip;        // network byte order, store-only
    std::vector<uint8_t> payload;
};

static uint16_t rd16_be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

// Strip Ethernet (+ optional 802.1Q VLAN) + IPv4 + L4 header. On any parse
// miss, fall back to the whole packet as payload with all-zero meta — the
// kernel will still process the bytes, just without port-offset matching.
static PktParsed parse_packet(const std::vector<uint8_t> &raw)
{
    PktParsed o = {};
    const uint8_t *p  = raw.data();
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
    if (etype != 0x0800) return fail_whole();     // not IPv4

    if (cur + 20 > rem) return fail_whole();
    const uint8_t *ip = p + cur;
    if ((ip[0] >> 4) != 4) return fail_whole();
    size_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || cur + ihl > rem) return fail_whole();

    o.ip_proto = ip[9];
    // 5-tuple: src/dst IP in network byte order (store-only on kernel side)
    memcpy(&o.src_ip, ip + 12, 4);
    memcpy(&o.dst_ip, ip + 16, 4);
    cur += ihl;

    size_t l4_off = cur;
    if (o.ip_proto == 6 /* TCP */) {
        if (l4_off + 20 > rem) return fail_whole();
        const uint8_t *tcp = p + l4_off;
        o.src_port = rd16_be(tcp + 0);
        o.dst_port = rd16_be(tcp + 2);
        size_t doff = ((tcp[12] >> 4) & 0xF) * 4;
        if (doff < 20 || l4_off + doff > rem) return fail_whole();
        cur = l4_off + doff;
    } else if (o.ip_proto == 17 /* UDP */) {
        if (l4_off + 8 > rem) return fail_whole();
        const uint8_t *udp = p + l4_off;
        o.src_port = rd16_be(udp + 0);
        o.dst_port = rd16_be(udp + 2);
        cur = l4_off + 8;
    } else if (o.ip_proto == 1 /* ICMP */) {
        if (l4_off + 2 > rem) return fail_whole();
        o.icmp_type = p[l4_off + 0];
        o.icmp_code = p[l4_off + 1];
        // ngram position 0 = first byte after Type/Code
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
        blob[db + 9]  = 0;
        w16(db + 10, m.src_port);
        w16(db + 12, m.dst_port);
        blob[db + 14] = m.icmp_type;
        blob[db + 15] = m.icmp_code;
        w32(db + 16, m.src_ip);        // 5-tuple
        w32(db + 20, m.dst_ip);        // 5-tuple
        // [db+24 .. db+32) reserved, left zero
        if (m.payload_len) {
            memcpy(blob.data() + cur_off, m.payload.data(), m.payload.size());
            cur_off += (uint32_t)m.payload.size();
            cur_off  = (cur_off + 63) & ~63u;
        }
    }

    return blob;
}

// Build the AXI4-Stream packet image for mm2s_pkt: one 128-byte record per beat.
//   word0 [0..64)  = tdata (payload, 64B)
//   word1 [64..72) = tkeep (8B), [72..88) = tuser (16B, 5-tuple), [88] = tlast
// tuser layout (matches PacketStreamReader.unpackTuser):
//   [31:0]srcIp [63:32]dstIp [71:64]proto [87:72]sport [103:88]dport
//   [111:104]icmpType [119:112]icmpCode
static std::vector<uint8_t> build_pkt_stream_image(const std::vector<PcapPkt> &pkts,
                                                   uint32_t &nbeats_out)
{
    std::vector<uint8_t> img;
    uint32_t nbeats = 0;
    for (auto &pp : pkts) {
        PktParsed m = parse_packet(pp.data);
        uint32_t plen = (uint32_t)m.payload.size();
        uint32_t nb   = (plen + 63) / 64;
        if (nb == 0) nb = 1;  // zero-payload packet still needs its tlast/meta beat

        uint8_t user[16] = {0};
        memcpy(user + 0, &m.src_ip, 4);
        memcpy(user + 4, &m.dst_ip, 4);
        user[8] = m.ip_proto;
        memcpy(user + 9,  &m.src_port, 2);
        memcpy(user + 11, &m.dst_port, 2);
        user[13] = m.icmp_type;
        user[14] = m.icmp_code;

        for (uint32_t b = 0; b < nb; b++) {
            bool     last   = (b == nb - 1);
            uint32_t off    = b * 64;
            uint32_t vbytes = (plen == 0) ? 0 : (last ? (plen - off) : 64);

            uint8_t beat[128];
            memset(beat, 0, sizeof(beat));
            if (vbytes) memcpy(beat, m.payload.data() + off, vbytes);

            uint64_t keep = (vbytes >= 64) ? ~0ULL
                          : (vbytes == 0)  ? 0ULL
                          : ((1ULL << vbytes) - 1);
            memcpy(beat + 64, &keep, 8);
            // Conformant to the Nixion final-beat-metadata AXIS model: tkeep/tuser
            // valid ONLY on the tlast beat. No first-beat sideband — the kernel now
            // derives the payload length from the beat count + last-beat tkeep
            // popcount. The last beat carries the 5-tuple in tuser.
            if (last) memcpy(beat + 72, user, 16);
            beat[88] = last ? 1 : 0;

            img.insert(img.end(), beat, beat + 128);
            nbeats++;
        }
    }
    nbeats_out = nbeats;
    return img;
}

// result:
// [0..256)            summary: 64 x u32 counters (4 x 64B lines)
// Per-packet records are intentionally dropped by the current ResultWriter.
static void print_results(const uint8_t *res, uint32_t pkt_count)
{
    uint32_t matched, processed, db_cyc, pkt_cyc, total_cyc;
    uint32_t dl_cyc, pr_cyc, pp_cyc, ng_cyc, bm_cyc, gm_cyc, ex_cyc, pom_cyc, rw_cyc;
    uint32_t grams_extracted, bitmap_passed, gram_lookups, gram_hits;
    uint32_t exact_checks, exact_hits, exact_misses, pom_checks, pom_hits, pom_misses, no_match_pkts;
    uint32_t stage2_checked, stage2_passed;
    uint32_t dl_e2e, pr_e2e, pp_e2e, ng_e2e, bm_e2e, gm_e2e, ex_e2e, pom_e2e, rw_e2e;
    uint32_t reader_desc, reader_start, reader_first_line_wait, reader_resp;
    uint32_t epoch_full, result_accept_block, exact_input_block;
    uint32_t bitmap_lookup_batches, bitmap_result_batches, bitmap_ngram_blocked, bitmap_tail_blocked;
    uint32_t bitmap_port_blocked, bitmap_side_blocked, bitmap_empty_batches;
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
    uint32_t gap_backend, gap_hbm, gap_reader_other, gap_meta_wait, gap_next_start;
    memcpy(&gap_backend,      res + 108, 4);
    memcpy(&gap_hbm,          res + 112, 4);
    memcpy(&gap_reader_other, res + 116, 4);
    memcpy(&gap_meta_wait,    res + 120, 4);
    memcpy(&gap_next_start,   res + 124, 4);
    memcpy(&dl_e2e,  res + 128, 4);
    memcpy(&pr_e2e,  res + 132, 4);
    memcpy(&pp_e2e,  res + 136, 4);
    memcpy(&ng_e2e,  res + 140, 4);
    memcpy(&bm_e2e,  res + 144, 4);
    memcpy(&gm_e2e,  res + 148, 4);
    memcpy(&ex_e2e,  res + 152, 4);
    memcpy(&pom_e2e, res + 156, 4);
    memcpy(&rw_e2e,  res + 160, 4);
    memcpy(&reader_desc,            res + 164, 4);
    memcpy(&reader_start,           res + 168, 4);
    memcpy(&reader_first_line_wait, res + 172, 4);
    memcpy(&reader_resp,            res + 176, 4);
    memcpy(&epoch_full,             res + 180, 4);
    memcpy(&result_accept_block,    res + 184, 4);
    memcpy(&exact_input_block,      res + 188, 4);
    memcpy(&bitmap_lookup_batches,  res + 192, 4);
    memcpy(&bitmap_result_batches,  res + 196, 4);
    memcpy(&bitmap_ngram_blocked,   res + 200, 4);
    memcpy(&bitmap_tail_blocked,    res + 204, 4);
    memcpy(&bitmap_port_blocked,    res + 208, 4);
    memcpy(&bitmap_side_blocked,    res + 212, 4);
    memcpy(&bitmap_empty_batches,   res + 216, 4);
    uint32_t bloom_cyc, bloom_e2e, bloom_rejects;
    memcpy(&bloom_cyc,     res + 220, 4);
    memcpy(&bloom_e2e,     res + 224, 4);
    memcpy(&bloom_rejects, res + 228, 4);
    printf("matched=%u  processed=%u\n", matched, processed);
    printf("cycles: db_load=%u  pkt_proc=%u  total=%u\n",
           db_cyc, pkt_cyc, total_cyc);
    printf("module_cycles (active): data_loader=%u  pkt_reader=%u  payload_feed=%u  ngram=%u  bitmap=%u  gram=%u  bloom=%u  exact=%u  pom=%u  result_writer=%u\n",
           dl_cyc, pr_cyc, pp_cyc, ng_cyc, bm_cyc, gm_cyc, bloom_cyc, ex_cyc, pom_cyc, rw_cyc);
    printf("module_cycles (e2e):    data_loader=%u  pkt_reader=%u  payload_feed=%u  ngram=%u  bitmap=%u  gram=%u  bloom=%u  exact=%u  pom=%u  result_writer=%u\n",
           dl_e2e, pr_e2e, pp_e2e, ng_e2e, bm_e2e, gm_e2e, bloom_e2e, ex_e2e, pom_e2e, rw_e2e);
    {
        uint32_t total_gap = gap_backend + gap_hbm + gap_reader_other + gap_meta_wait;
        double   gap_pct   = pkt_cyc ? 100.0 * (double)total_gap / (double)pkt_cyc : 0.0;
        double   avg_gap   = (processed > 1) ? (double)gap_next_start / (double)(processed - 1) : 0.0;
        printf("interpacket: gap_backend=%u  gap_hbm=%u  gap_reader_other=%u  gap_meta_wait=%u  total_gap=%u (%.1f%% of pkt_proc)  avg_next_start_gap=%.1f cycles/pkt\n",
               gap_backend, gap_hbm, gap_reader_other, gap_meta_wait, total_gap, gap_pct, avg_gap);
        printf("reader_breakdown: desc=%u  start=%u  first_line_wait=%u  payload_resp_overlap=%u\n",
               reader_desc, reader_start, reader_first_line_wait, reader_resp);
        printf("backpressure: epoch_full=%u  result_accept_block=%u  exact_input_block=%u\n",
               epoch_full, result_accept_block, exact_input_block);
        printf("bitmap_pipe: lookup_batches=%u  result_batches=%u  ngram_blocked=%u  tail_blocked=%u  port_blocked=%u  side_blocked=%u  empty_batches=%u\n",
               bitmap_lookup_batches, bitmap_result_batches, bitmap_ngram_blocked,
               bitmap_tail_blocked, bitmap_port_blocked, bitmap_side_blocked,
               bitmap_empty_batches);
    }
    auto pct = [](uint32_t hit, uint32_t total) {
        return total ? 100.0 * (double)hit / (double)total : 0.0;
    };
    auto row = [&](const char *name, uint32_t hit, uint32_t total) {
        // Chain expansion (multi-rule per gram) can make hit > total at the
        // hashtable stage — one cuckoo lookup yields N candidate rules.
        // Show that as "+N chain"; standard filter drops show as a number.
        int64_t diff = (int64_t)total - (int64_t)hit;
        char buf[24];
        if (diff < 0) snprintf(buf, sizeof buf, "+%lld chain", (long long)-diff);
        else          snprintf(buf, sizeof buf, "%lld", (long long)diff);
        printf("  %-10s  %10u  %10u  %12s  %7.2f%%\n",
               name, total, hit, buf, pct(hit, total));
    };
    printf("=== per-stage gram filter ===\n");
    printf("  %-10s  %10s  %10s  %12s  %8s\n",
           "stage", "total", "hit", "miss/chain", "pass%");
    row("bitmap0",   bitmap_passed, grams_extracted);
    row("bitmap1",   stage2_passed, stage2_checked);
    row("hashtable", gram_hits,     gram_lookups);
    row("exact",     exact_hits,    exact_checks);
    row("pom",       pom_hits,      pom_checks);
    printf("no_match_pkts=%u\n", no_match_pkts);
    {
        // gram_lookups is counted pre-bloom (bitmap survivors needing cuckoo);
        // the bloom kills bloom_rejects of them before any cuckoo bank lookup.
        uint32_t cuckoo_real = (gram_lookups >= bloom_rejects)
                             ? gram_lookups - bloom_rejects : 0;
        double rej_pct = gram_lookups ? 100.0 * (double)bloom_rejects / (double)gram_lookups : 0.0;
        printf("bloom: tested=%u  rejected=%u (%.1f%%)  cuckoo_lookups=%u  active_cyc=%u  e2e_cyc=%u\n",
               gram_lookups, bloom_rejects, rej_pct, cuckoo_real, bloom_cyc, bloom_e2e);
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

    uint32_t pkt_nbeats = 0;
    auto pkt_img = build_pkt_stream_image(pkts, pkt_nbeats);
    printf("pkt stream image: %zu bytes, %u beats\n", pkt_img.size(), pkt_nbeats);

    uint32_t pkt_count = (uint32_t)pkts.size();
    // Result AXI Stream: header beat (db_load cycles) + one {match,ruleId} beat
    // per packet + footer beat (total process cycles). Buffer = (pkt_count+2) u32.
    uint32_t res_beats = pkt_count + 2;
    size_t res_size = (size_t)res_beats * 4;

    xrt::device device{0u};
    xrt::uuid   uuid = device.load_xclbin(xclbin_path);
    // Kernel is free-running (ap_ctrl_none) -> NOT host-launched. We only drive the
    // three data movers; the kernel processes whatever arrives on its streams.
    auto mm2s_db  = xrt::kernel(device, uuid, "mm2s_db:{mm2s_db_1}");
    auto mm2s_pkt = xrt::kernel(device, uuid, "mm2s_pkt:{mm2s_pkt_1}");
    auto s2mm     = xrt::kernel(device, uuid, "s2mm:{s2mm_1}");

    auto boDb   = xrt::bo(device, db_size,        mm2s_db.group_id(0));
    auto boPkt  = xrt::bo(device, pkt_img.size(), mm2s_pkt.group_id(0));
    auto boRes  = xrt::bo(device, res_size,       s2mm.group_id(0));

    memcpy(boDb.map<uint8_t *>(),  db_blob.data(), db_size);
    memcpy(boPkt.map<uint8_t *>(), pkt_img.data(), pkt_img.size());
    memset(boRes.map<uint8_t *>(), 0,              res_size);

    boDb.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    boPkt.sync(XCL_BO_SYNC_BO_TO_DEVICE);
    boRes.sync(XCL_BO_SYNC_BO_TO_DEVICE);

    uint32_t db_words = (uint32_t)((db_size + 63) / 64);
    printf("driving 3 movers (db_words=%u, pkt_beats=%u); kernel free-runs...\n", db_words, pkt_nbeats);

    // set_arg by index: stream arg (id 1) skipped. movers: mem(0), s(1 stream), count(2).
    // Start s2mm (consumer) first; the free-running kernel loads DB first (packets
    // backpressure until DB done), then matches. Sync point = s2mm reads pkt_count beats.
    xrt::run m_run(mm2s_db);
    m_run.set_arg(0, boDb);
    m_run.set_arg(2, db_words);
    xrt::run p_run(mm2s_pkt);
    p_run.set_arg(0, boPkt);
    p_run.set_arg(2, pkt_nbeats);
    xrt::run r_run(s2mm);
    r_run.set_arg(0, boRes);
    r_run.set_arg(2, res_beats);   // header beat + one per packet

    long wait_s = 120 + (long)db_words / 100;   // ~120s + headroom for big DBs
    auto chk = [wait_s](const char *nm, xrt::run &r) {
        ert_cmd_state st = r.wait(std::chrono::seconds(wait_s));
        printf("  %-9s -> %s\n", nm,
               (st == ERT_CMD_STATE_COMPLETED) ? "COMPLETED" : "*** STUCK (timeout) ***");
    };
    r_run.start();   // consumer first
    m_run.start();   // db
    p_run.start();   // packets

    chk("mm2s_db",  m_run);
    chk("mm2s_pkt", p_run);
    chk("s2mm",     r_run);
    printf("done\n");

    boRes.sync(XCL_BO_SYNC_BO_FROM_DEVICE);
    const uint32_t *res = boRes.map<uint32_t *>();

    // Beat 0 = db_load cycle count (header). Beats 1..pkt_count = per-packet
    // results: bit0 = matched, bits[16:1] = ruleId, bits[31:17] = E2E latency
    // (admit->retire cycles, 15-bit saturated).
    uint32_t db_load_cycles = res[0];               // header beat
    uint32_t proc_cycles    = res[pkt_count + 1];    // footer beat
    printf("=== per-packet results (from m_axis_result stream) ===\n");
    uint32_t matched = 0;
    for (uint32_t i = 0; i < pkt_count; i++) {
        uint32_t r = res[i + 1];           // +1: skip header beat
        bool     m = (r & 1u) != 0;
        uint16_t rule_id = (uint16_t)((r >> 1) & 0xFFFFu);
        if (m) { printf("  pkt[%u] matched rule_id=%u\n", i, rule_id); matched++; }
    }
    printf("matched=%u  processed=%u\n", matched, pkt_count);
    printf("=== cycles: db_load=%u  process=%u (%u pkts)  =>  %.2f cycles/pkt ===\n",
           db_load_cycles, proc_cycles, pkt_count,
           pkt_count ? (double)proc_cycles / pkt_count : 0.0);

    return EXIT_SUCCESS;
}
