#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "rule_loader.h"
#include "ngram_extract.h"
#include "singleton.h"
#include "bitmap.h"
#include "match.h"
#include "exact_match.h"
#include "pcap_reader.h"
#include "packet_parser.h"

#define N 3
// #define MAX_STAGE 4

static int cmp_gram(const void *a, const void *b) { return memcmp(a, b, N); }

static void print_gram(const uint8_t *g)
{
    for (int i = 0; i < N; i++) {
        if (g[i] >= 0x20 && g[i] < 0x7f) printf("%c", g[i]);
        else                               printf("\\x%02x", g[i]);
    }
}

int main(int argc, char *argv[])
{
    const char *rule_file = (argc > 1) ? argv[1] : "rule.txt";
    const char *pcap_file = (argc > 2) ? argv[2] : NULL;
    const char MAX_STAGE = (argc > 3) ? atoi(argv[3]) : 4;
    const char verbose = (argc > 4) ? atoi(argv[3]) : 1;

    RuleSet *rs = rules_load(rule_file);
    if (!rs) {
        fprintf(stderr, "failed to load: %s\n", rule_file);
        return 1;
    }

    int total_bytes = 0, min_len = 999999, max_len = 0, total_grams = 0;
    for (int i = 0; i < rs->count; i++) {
        int l = rs->rules[i].pat_len;
        total_bytes += l;
        if (l < min_len) min_len = l;
        if (l > max_len) max_len = l;
        if (l >= N) total_grams += l - N + 1;
    }

    printf("file       : %s\n", rule_file);
    printf("rules      : %d\n", rs->count);
    printf("pat min    : %d bytes\n", min_len);
    printf("pat max    : %d bytes\n", max_len);
    printf("pat avg    : %.1f bytes\n", rs->count ? (double)total_bytes / rs->count : 0.0);
    printf("n          : %d\n", N);
    printf("total grams: %d\n", total_grams);

    uint8_t *buf = malloc(total_grams * N);
    int idx = 0;
    for (int i = 0; i < rs->count; i++) {
        Rule *r = &rs->rules[i];
        NGramSet *ns = ngram_extract((uint8_t *)r->pattern, r->pat_len, N);
        if (!ns) continue;
        memcpy(buf + idx * N, ns->data, ns->count * N);
        idx += ns->count;
        ngram_free(ns);
    }
    qsort(buf, total_grams, N, cmp_gram);

    int unique = 0;
    for (int i = 0; i < total_grams; i++)
        if (i == 0 || memcmp(buf + i*N, buf + (i-1)*N, N) != 0) unique++;

    printf("unique %d-grams: %d\n\n", N, unique);
    free(buf);

    printf("=== singleton build ===\n");
    SingletonResult *sr = singleton_build(rs, MAX_STAGE);
    if (!sr) {
        fprintf(stderr, "singleton_build failed\n");
        rules_free(rs);
        return 1;
    }

    int n_singleton = 0, n_shared = 0;
    for (int i = 0; i < sr->count; i++) {
        if (sr->assigns[i].degree == 1) n_singleton++;
        else                            n_shared++;
    }

    printf("covered    : %d\n", sr->count);
    printf("uncovered  : %d  (pat_len < 3)\n", sr->uncovered);
    printf("singletons : %d  (degree=1, unique gram)\n", n_singleton);
    printf("shared     : %d  (degree>1, gram in multiple rules)\n\n", n_shared);


    if (verbose > 0) {
        printf("%-6s  %-10s  %-5s  %-4s  %-4s  %-3s  %-5s  %s\n",
            "ruleid", "gram", "pos", "pre", "post", "deg", "stage", "next_grams");
        printf("------  ----------  -----  ----  ----  ---  -----  ----------\n");


        int print_range = (verbose > 1) ? sr->count : (n_singleton < 5 ? sr->count : 5);

        for (int i = 0; i < print_range; i++) {
            GramAssign *a = &sr->assigns[i];
            printf("%-6d  ", a->rule_id);
            print_gram(a->gram);
            printf("%-7s  %-5d  %-4d  %-4d  %-3d  %-5d  ",
                "", a->gram_pos, a->pre_offset, a->post_offset, a->degree, a->stage);
            if (a->next_grams) {
                for (int j = 0; j < a->stage - 1; j++) {
                    print_gram(&a->next_grams[j * N]);
                }
            }
            printf("\n");
        }
    }

    printf("\n=== bitmap build ===\n");
    Bitmap *bm = calloc(1, sizeof(Bitmap));
    bitmap_clear(bm);
    for (int i = 0; i < sr->count; i++)
        bitmap_set_gram(bm, sr->assigns[i].gram);

    Bitmap* bm_arr = malloc(MAX_STAGE * sizeof(Bitmap));
    Bitmap* bm_verifier_arr = malloc((MAX_STAGE-1) * sizeof(Bitmap));
    for (int i=0; i < (MAX_STAGE-1); i ++)
        bitmap_clear(bm_verifier_arr + i);
    for (int i=0; i < MAX_STAGE; i ++)
        bitmap_clear(bm_arr + i);

    for (int i = 0; i < sr->count; i++) {
        uint8_t* gram = sr->assigns[i].gram;
        int stage = sr->assigns[i].stage;
        bitmap_set_gram(bm_arr, gram);

        for (int cur_stage = 1; cur_stage < stage; cur_stage++) {
            Bitmap* current_verifier = bm_verifier_arr + (cur_stage-1);
            bitmap_set_gram(current_verifier, gram);

            uint8_t next_gram[N];
            memcpy(
                next_gram,
                sr->assigns[i].next_grams + ((cur_stage - 1) * N),
                (size_t)N
            );
            Bitmap* current_stage = bm_arr + cur_stage;
            bitmap_set_gram(current_stage, next_gram);
        }
    }


    int verify_ok = 1;
    for (int i = 0; i < sr->count; i++) {
        if (!bitmap_test_gram(bm, sr->assigns[i].gram)) {
            fprintf(stderr, "bitmap verify FAIL rule_id=%d\n", sr->assigns[i].rule_id);
            verify_ok = 0;
        }
    }

    int bits_set = 0;
    for (int i = 0; i < (int)BITMAP_BYTES; i++) {
        uint8_t b = bm->data[i];
        while (b) { bits_set += b & 1; b >>= 1; }
    }

    bool ms_verify_res = verify_ms_bitmap(bm_arr, bm_verifier_arr, sr);

    printf("grams in bitmap     : %d\n", bits_set);
    printf("bitmap size         : %d bytes (256KB)\n", (int)BITMAP_BYTES);
    printf("verify              : %s\n", verify_ok ? "OK" : "FAIL");
    printf("ms_verify           : %s\n", ms_verify_res ? "OK" : "FAIL");

    printf("\n=== matching stage ===\n");
    MatchCtx        mctx;
    MatchCandidate  candidates[1024];
    MatchResult     matches[256];
    match_init(&mctx, sr);

    if (pcap_file) {
        PcapReader *pr = pcap_open(pcap_file);
        if (!pr) {
            fprintf(stderr, "failed to open pcap: %s\n", pcap_file);
        } else {
            printf("pcap           : %s\n", pcap_file);
            PcapFrame frame;
            int n_frames = 0, n_parsed = 0, n_matched_pkts = 0;
            int n_bm_pkts = 0;

            while (pcap_next(pr, &frame)) {
                n_frames++;
                Packet pkt;
                if (packet_parse(frame.data, frame.caplen, &pkt) < 0
                    || pkt.payload_len == 0) {
                    pcap_frame_free(&frame);
                    continue;
                }
                n_parsed++;

                int nc = match_scan(&mctx, pkt.payload, (int)pkt.payload_len,
                                    bm, candidates, 1024);
                if (nc > 0) n_bm_pkts++;

                int nm = exact_match(pkt.payload, (int)pkt.payload_len,
                                     candidates, nc < 1024 ? nc : 1024,
                                     rs, matches, 256);
                if (nm > 0) n_matched_pkts++;
                
                if (verbose > 1) {
                    for (int j = 0; j < nm; j++)
                        printf("  [ALERT] frame=%-5d  rule=%-4d  anchor=%-4d\n",
                            n_frames, matches[j].rule_id, matches[j].anchor);
                }
                pcap_frame_free(&frame);
            }

            printf("frames total   : %d\n", n_frames);
            printf("frames parsed  : %d  (IPv4/IPv6 TCP/UDP/ICMP with payload)\n", n_parsed);
            printf("bitmap hit pkts: %d / %d  (%.1f%%)\n",
                   n_bm_pkts, n_parsed,
                   n_parsed ? 100.0 * n_bm_pkts / n_parsed : 0.0);
            printf("matched packets: %d / %d  (%.1f%%)\n",
                   n_matched_pkts, n_parsed,
                   n_parsed ? 100.0 * n_matched_pkts / n_parsed : 0.0);
            pcap_close(pr);
        }
    } else {
        int fn = 0, total_bm = 0, total_exact = 0;
        for (int i = 0; i < rs->count; i++) {
            const Rule *r = &rs->rules[i];
            if (r->pat_len < 3) continue;

            int nc = match_scan(&mctx, (const uint8_t *)r->pattern, r->pat_len,
                                bm, candidates, 1024);
            total_bm += nc;

            int nm = exact_match((const uint8_t *)r->pattern, r->pat_len,
                                 candidates, nc < 1024 ? nc : 1024,
                                 rs, matches, 256);
            total_exact += nm;

            int found = 0;
            for (int j = 0; j < nm; j++)
                if (matches[j].rule_id == r->id) { found = 1; break; }
            if (!found) fn++;
        }
        printf("rules scanned   : %d\n", rs->count);
        printf("bitmap hits     : %d  (potential match candidates)\n", total_bm);
        printf("exact matches   : %d\n", total_exact);
        printf("false negatives : %d\n", fn);

        printf("\nSample self-matches (first 5 eligible rules):\n");
        printf("  %-6s  %-6s  %-8s  %s\n", "ruleid", "anchor", "gram", "pattern (first 20 bytes)");
        int shown = 0;
        for (int i = 0; i < rs->count && shown < 5; i++) {
            const Rule *r = &rs->rules[i];
            if (r->pat_len < 3) continue;
            int nc = match_scan(&mctx, (const uint8_t *)r->pattern, r->pat_len,
                                bm, candidates, 1024);
            int nm = exact_match((const uint8_t *)r->pattern, r->pat_len,
                                 candidates, nc < 1024 ? nc : 1024,
                                 rs, matches, 256);
            for (int j = 0; j < nm; j++) {
                if (matches[j].rule_id != r->id) continue;
                int anch = matches[j].anchor;
                printf("  %-6d  %-6d  %02x%02x%02x    \"%.20s\"\n",
                       r->id, anch,
                       (uint8_t)r->pattern[anch],
                       (uint8_t)r->pattern[anch+1],
                       (uint8_t)r->pattern[anch+2],
                       r->pattern);
                shown++;
                break;
            }
        }
    }

    match_destroy(&mctx);

    free(bm);
    free(bm_arr);
    free(bm_verifier_arr);
    singleton_free(sr);
    rules_free(rs);
    return 0;
}
