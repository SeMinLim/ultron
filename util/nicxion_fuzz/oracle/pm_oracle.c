// Per-packet reference oracle for the nicxion PM kernel.
//
// Same pipeline as ~/Tests/cref_bench (match_scan -> exact_match ->
// port_offset_match -> priority_sort, max_stage 2), but instead of a timing
// run it prints one line per pcap record, indexed exactly like the host
// program's pkt[i] (every record counts, parseable or not):
//
//   <idx> SKIP                                  parse failure or empty payload
//   <idx> MISS
//   <idx> HIT <best_prio> <top_ids> <all>       top_ids = every rule tied at the
//                                               best priority (comma list);
//                                               all = id:prio for every match
//
// The tie group matters: HW and C break priority ties differently (see
// PRIORITY_TIEBREAK_TODO.md), so the fuzzer accepts any id in top_ids.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rule_loader.h"
#include "singleton.h"
#include "bitmap.h"
#include "match.h"
#include "exact_match.h"
#include "port_offset_matcher.h"
#include "priority.h"
#include "packet_parser.h"
#include "pcap_reader.h"

#define MAX_STAGE 2

// ---- spec matcher ---------------------------------------------------------
// Ground truth for the kernel: every occurrence of every (case-folded) pattern.
// The kernel's bitmap / bloom / cuckoo stages are filters built to have no
// false negatives, so this is what it must reproduce.  The C gram pipeline
// (--match cref) has quirks of its own, e.g. it drops a stage-1 rule whose
// anchor gram also anchors a stage-2 rule when the next gram is missing.
static int *spec_order;   // rule indices sorted by 3-byte prefix
static uint32_t *spec_key;
static int spec_n, *spec_short, spec_nshort;

static uint32_t pfx(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }
static const RuleSet *g_rs_spec;
static int cmp_pfx(const void *a, const void *b) {
    uint32_t x = pfx((const uint8_t *)g_rs_spec->rules[*(const int *)a].pattern);
    uint32_t y = pfx((const uint8_t *)g_rs_spec->rules[*(const int *)b].pattern);
    return x < y ? -1 : x > y;
}
static void spec_init(const RuleSet *rs) {
    g_rs_spec = rs;
    spec_order = malloc((size_t)rs->count * sizeof(int));
    spec_short = malloc((size_t)rs->count * sizeof(int));
    spec_n = spec_nshort = 0;
    for (int i = 0; i < rs->count; i++) {
        if (rs->rules[i].pat_len >= 3) spec_order[spec_n++] = i;
        else if (rs->rules[i].pat_len > 0) spec_short[spec_nshort++] = i;
    }
    qsort(spec_order, (size_t)spec_n, sizeof(int), cmp_pfx);
    spec_key = malloc((size_t)spec_n * sizeof(uint32_t) + 1);
    for (int i = 0; i < spec_n; i++) spec_key[i] = pfx((const uint8_t *)rs->rules[spec_order[i]].pattern);
}
static int spec_scan(const RuleSet *rs, const uint8_t *b, int len, MatchResult *out, int out_max) {
    int n = 0;
    for (int pos = 0; pos < len; pos++) {
        for (int k = 0; k < spec_nshort; k++) {
            const Rule *r = &rs->rules[spec_short[k]];
            if (pos + r->pat_len <= len && !memcmp(b + pos, r->pattern, (size_t)r->pat_len)) {
                if (n < out_max) out[n] = (MatchResult){ r->id, pos, pos };
                n++;
            }
        }
        if (pos + 3 > len) continue;
        uint32_t key = pfx(b + pos);
        int lo = 0, hi = spec_n;                       // first index with spec_key >= key
        while (lo < hi) { int m = (lo + hi) / 2; if (spec_key[m] < key) lo = m + 1; else hi = m; }
        for (int j = lo; j < spec_n && spec_key[j] == key; j++) {
            const Rule *r = &rs->rules[spec_order[j]];
            if (pos + r->pat_len <= len && !memcmp(b + pos, r->pattern, (size_t)r->pat_len)) {
                if (n < out_max) out[n] = (MatchResult){ r->id, pos, pos };
                n++;
            }
        }
    }
    return n;
}

static uint16_t rd16_be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

// Byte-for-byte port of parse_packet() in the host program (main.cpp): this is
// what the kernel actually receives (payload bytes + tuser metadata).  Differs
// from the C reference parser: payload runs to the end of the frame (not the IP
// total length), non-TCP/UDP/ICMP protocols keep their L4 bytes as payload, and
// proto 58 is not treated as ICMP.  On failure the whole frame becomes the
// payload but the fields filled in so far are kept (same as the host lambda).
static void host_parse(const uint8_t *p, size_t rem, Packet *o) {
    memset(o, 0, sizeof(*o));
    size_t cur;
#define FAIL_WHOLE do { o->payload = p; o->payload_len = rem; return; } while (0)
    if (rem < 14) FAIL_WHOLE;
    uint16_t etype = rd16_be(p + 12);
    cur = 14;
    while (etype == 0x8100 && cur + 4 <= rem) { etype = rd16_be(p + cur + 2); cur += 4; }
    if (etype != 0x0800) FAIL_WHOLE;
    if (cur + 20 > rem) FAIL_WHOLE;
    const uint8_t *ip = p + cur;
    if ((ip[0] >> 4) != 4) FAIL_WHOLE;
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
    if (ihl < 20 || cur + ihl > rem) FAIL_WHOLE;
    o->proto = ip[9];
    cur += ihl;
    size_t l4 = cur;
    if (o->proto == 6) {
        if (l4 + 20 > rem) FAIL_WHOLE;
        o->src_port = rd16_be(p + l4);
        o->dst_port = rd16_be(p + l4 + 2);
        size_t doff = (size_t)((p[l4 + 12] >> 4) & 0xF) * 4;
        if (doff < 20 || l4 + doff > rem) FAIL_WHOLE;
        cur = l4 + doff;
    } else if (o->proto == 17) {
        if (l4 + 8 > rem) FAIL_WHOLE;
        o->src_port = rd16_be(p + l4);
        o->dst_port = rd16_be(p + l4 + 2);
        cur = l4 + 8;
    } else if (o->proto == 1) {
        if (l4 + 2 > rem) FAIL_WHOLE;
        o->icmp_type = p[l4];
        o->icmp_code = p[l4 + 1];
        cur = l4 + 2;
    } else {
        cur = l4;
    }
#undef FAIL_WHOLE
    o->payload = p + cur;
    o->payload_len = rem - cur;
}

// Port of parse_packet() in sw/host_nicxion_rev2_ipv6/main.cpp (--parser host6):
// the host above plus IPv6 (extension headers 0/43/60/44; AH/ESP stay the
// protocol; ICMPv6 58 takes type/code like ICMP), IPv4 non-first fragments
// (no L4 header), the payload cut at the IP datagram length (Ethernet padding
// dropped; IPv4 total length 0 = TSO capture keeps the frame), and QinQ tags.
static void host6_parse(const uint8_t *p, size_t rem, Packet *o) {
    memset(o, 0, sizeof(*o));
    const size_t full = rem;
    size_t cur;
#define FAIL_WHOLE do { o->payload = p; o->payload_len = full; return; } while (0)
    if (rem < 14) FAIL_WHOLE;
    uint16_t etype = rd16_be(p + 12);
    cur = 14;
    while ((etype == 0x8100 || etype == 0x88A8 || etype == 0x9100) && cur + 4 <= rem) {
        etype = rd16_be(p + cur + 2); cur += 4;
    }
    int l4_present = 1;
    if (etype == 0x0800) {
        if (cur + 20 > rem) FAIL_WHOLE;
        const uint8_t *ip = p + cur;
        if ((ip[0] >> 4) != 4) FAIL_WHOLE;
        size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
        if (ihl < 20 || cur + ihl > rem) FAIL_WHOLE;
        size_t tot = rd16_be(ip + 2);
        if (tot != 0) {
            if (tot < ihl) FAIL_WHOLE;
            if (cur + tot < rem) rem = cur + tot;
        }
        o->proto = ip[9];
        if ((rd16_be(ip + 6) & 0x1FFF) != 0) l4_present = 0;
        cur += ihl;
    } else if (etype == 0x86DD) {
        if (cur + 40 > rem) FAIL_WHOLE;
        const uint8_t *ip = p + cur;
        if ((ip[0] >> 4) != 6) FAIL_WHOLE;
        uint16_t plen6 = rd16_be(ip + 4);
        if (plen6 != 0 && cur + 40 + plen6 < rem) rem = cur + 40 + plen6;
        uint8_t nh = ip[6];
        cur += 40;
        for (int hops = 0; hops < 8; hops++) {
            if (nh == 0 || nh == 43 || nh == 60) {
                if (cur + 8 > rem) FAIL_WHOLE;
                size_t len = ((size_t)p[cur + 1] + 1) * 8;
                if (cur + len > rem) FAIL_WHOLE;
                nh = p[cur]; cur += len;
            } else if (nh == 44) {
                if (cur + 8 > rem) FAIL_WHOLE;
                uint16_t off = rd16_be(p + cur + 2) >> 3;
                nh = p[cur]; cur += 8;
                if (off != 0) { l4_present = 0; break; }
            } else break;
        }
        o->proto = nh;
    } else FAIL_WHOLE;
    size_t l4 = cur;
    if (!l4_present) {
        cur = l4;
    } else if (o->proto == 6) {
        if (l4 + 20 > rem) FAIL_WHOLE;
        o->src_port = rd16_be(p + l4);
        o->dst_port = rd16_be(p + l4 + 2);
        size_t doff = (size_t)((p[l4 + 12] >> 4) & 0xF) * 4;
        if (doff < 20 || l4 + doff > rem) FAIL_WHOLE;
        cur = l4 + doff;
    } else if (o->proto == 17) {
        if (l4 + 8 > rem) FAIL_WHOLE;
        o->src_port = rd16_be(p + l4);
        o->dst_port = rd16_be(p + l4 + 2);
        cur = l4 + 8;
    } else if (o->proto == 1 || o->proto == 58) {
        if (l4 + 2 > rem) FAIL_WHOLE;
        o->icmp_type = p[l4];
        o->icmp_code = p[l4 + 1];
        cur = l4 + 2;
    } else {
        cur = l4;
    }
#undef FAIL_WHOLE
    o->payload = p + cur;
    o->payload_len = rem - cur;
}

int main(int argc, char **argv) {
    // --parser host (default): judge the kernel on what the host fed it.
    // --parser host6: the IPv6-capable host (sw/host_nicxion_rev2_ipv6).
    // --parser cref: the C reference parser (for studying parser divergence).
    // --match spec (default): brute-force ground truth.  --match cref: the C
    // reference gram pipeline (to measure the reference's own deviations).
    int use_host = 1, use_host6 = 0, use_spec = 1;
    for (int i = 3; i + 1 < argc; i += 2) {
        if      (!strcmp(argv[i], "--parser")) { use_host = strcmp(argv[i + 1], "cref") != 0;
                                                 use_host6 = !strcmp(argv[i + 1], "host6"); }
        else if (!strcmp(argv[i], "--match"))  use_spec = strcmp(argv[i + 1], "cref") != 0;
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 2; }
    }
    if (argc < 3 || (argc - 3) % 2) {
        fprintf(stderr, "usage: %s <rule_file> <pcap> [--parser host|host6|cref] [--match spec|cref]\n", argv[0]);
        return 2;
    }
    RuleSet *rs = rules_load(argv[1]);
    if (!rs) { fprintf(stderr, "failed to load rules: %s\n", argv[1]); return 1; }
    SingletonResult *sr = singleton_build(rs, MAX_STAGE);
    if (!sr) { fprintf(stderr, "singleton_build failed\n"); return 1; }

    Bitmap bm_arr[MAX_STAGE], bm_verifier_arr[MAX_STAGE - 1];
    for (int i = 0; i < MAX_STAGE - 1; i++) bitmap_clear(bm_verifier_arr + i);
    for (int i = 0; i < MAX_STAGE;     i++) bitmap_clear(bm_arr + i);
    for (int i = 0; i < sr->count; i++) {
        uint8_t *gram = sr->assigns[i].gram;
        int stage = sr->assigns[i].stage;
        bitmap_set_gram(bm_arr, gram);
        for (int cur = 1; cur < stage; cur++) {
            bitmap_set_gram(bm_verifier_arr + (cur - 1), gram);
            uint8_t next_gram[3];
            memcpy(next_gram, sr->assigns[i].next_grams + ((cur - 1) * 3), 3);
            bitmap_set_gram(bm_arr + cur, next_gram);
        }
    }
    MatchCtx mctx;
    match_init(&mctx, sr);
    spec_init(rs);

    // Results carry the rule's file id (find_rule looks rules up by id), so
    // map id -> priority instead of indexing rs->rules by it.
    int max_id = 0;
    for (int i = 0; i < rs->count; i++) if (rs->rules[i].id > max_id) max_id = rs->rules[i].id;
    int *prio_of = calloc((size_t)max_id + 1, sizeof(int));
    for (int i = 0; i < rs->count; i++) prio_of[rs->rules[i].id] = rs->rules[i].priority;

    PcapReader *pr = pcap_open(argv[2]);
    if (!pr) { fprintf(stderr, "failed to open pcap: %s\n", argv[2]); return 1; }

    int cap = 1024;
    MatchCandidate *cand = malloc((size_t)cap * sizeof(MatchCandidate));
    // exact_match returns the full match count even when it exceeds out_max
    // (it only writes out_max entries), and cref_bench passes that count on to
    // port_offset_match -> out-of-bounds read.  Grow and retry instead.
    int mcap = 256;
    MatchResult *matches  = malloc((size_t)mcap * sizeof(MatchResult));
    MatchResult *filtered = malloc((size_t)mcap * sizeof(MatchResult));
    PcapFrame frame;
    long idx = 0, hits = 0;
    while (pcap_next(pr, &frame)) {
        Packet pkt;
        if (use_host) {
            if (use_host6) host6_parse(frame.data, frame.caplen, &pkt);
            else           host_parse(frame.data, frame.caplen, &pkt);   // never skips: the kernel sees every record
        } else if (packet_parse(frame.data, frame.caplen, &pkt) < 0 || pkt.payload_len == 0) {
            printf("%ld SKIP\n", idx++);
            pcap_frame_free(&frame);
            continue;
        }
        size_t len = pkt.payload_len < 65536 ? pkt.payload_len : 65536;
        uint8_t *b = malloc(len);
        for (size_t i = 0; i < len; i++) {
            uint8_t c = pkt.payload[i];
            b[i] = (c >= 0x41 && c <= 0x5A) ? (uint8_t)(c | 0x20) : c;
        }
        Packet meta = pkt; meta.payload = b; meta.payload_len = len;

        int nm;
        if (use_spec) {
            nm = spec_scan(rs, b, (int)len, matches, mcap);
            if (nm > mcap) {
                mcap = nm;
                matches  = realloc(matches,  (size_t)mcap * sizeof(MatchResult));
                filtered = realloc(filtered, (size_t)mcap * sizeof(MatchResult));
                nm = spec_scan(rs, b, (int)len, matches, mcap);
            }
        } else {
            MatchCount mc = match_scan(&mctx, b, (int)len, bm_arr, bm_verifier_arr, cand, cap, MAX_STAGE);
            while (mc.nc > cap) {
                cap = mc.nc;
                cand = realloc(cand, (size_t)cap * sizeof(MatchCandidate));
                mc = match_scan(&mctx, b, (int)len, bm_arr, bm_verifier_arr, cand, cap, MAX_STAGE);
            }
            nm = exact_match(b, (int)len, cand, mc.nc, rs, matches, mcap);
            if (nm > mcap) {
                mcap = nm;
                matches  = realloc(matches,  (size_t)mcap * sizeof(MatchResult));
                filtered = realloc(filtered, (size_t)mcap * sizeof(MatchResult));
                nm = exact_match(b, (int)len, cand, mc.nc, rs, matches, mcap);
            }
        }
        int nf = port_offset_match(matches, nm, rs, &meta, filtered, mcap);
        priority_sort(filtered, nf, rs);

        if (nf == 0) {
            printf("%ld MISS\n", idx);
        } else {
            hits++;
            int best = prio_of[filtered[0].rule_id];
            for (int i = 1; i < nf; i++) {
                int p = prio_of[filtered[i].rule_id];
                if (p > best) best = p;
            }
            printf("%ld HIT %d ", idx, best);
            int first = 1;
            for (int i = 0; i < nf; i++)
                if (prio_of[filtered[i].rule_id] == best) {
                    printf(first ? "%d" : ",%d", filtered[i].rule_id); first = 0;
                }
            printf(" ");
            for (int i = 0; i < nf; i++)
                printf(i ? ",%d:%d" : "%d:%d", filtered[i].rule_id,
                       prio_of[filtered[i].rule_id]);
            printf("\n");
        }
        free(b);
        pcap_frame_free(&frame);
        idx++;
    }
    pcap_close(pr);
    fprintf(stderr, "oracle: %ld records, %ld hits\n", idx, hits);
    return 0;
}
