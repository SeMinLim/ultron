#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <malloc.h>
#include "rule_loader.h"
#include "ngram_extract.h"
#include "singleton.h"
#include "bitmap.h"
#include "match.h"
#include "exact_match.h"
#include "port_offset_matcher.h"
#include "priority.h"
#include "pm_output.h"
#include "pcap_reader.h"
#include "packet_parser.h"

#define N 3
static int cmp_gram(const void *a, const void *b) { return memcmp(a, b, N); }

static void print_gram(const uint8_t *g)
{
    for (int i = 0; i < N; i++) {
        if (g[i] >= 0x20 && g[i] < 0x7f) printf("%c", g[i]);
        else                               printf("\\x%02x", g[i]);
    }
}

static void print_memory_usage(const char *label, size_t bytes)
{
    printf("%-24s: %zu bytes (%.2f KiB, %.2f MiB)\n",
           label, bytes, (double)bytes / 1024.0, (double)bytes / (1024.0 * 1024.0));
}

static size_t allocation_usable_bytes(void *ptr)
{
    return ptr ? malloc_usable_size(ptr) : 0;
}

static void print_hash_table_usage(const MatchCtx *ctx)
{
    int total_entries = 0, total_slots = 0;
    size_t total_occ = 0, total_req = 0, total_run = 0;
    printf("hash banks         : %d\n", HT_BANKS);
    printf("  %-4s  %-8s  %-8s  %-7s\n", "bank", "entries", "slots", "load%");
    for (int b = 0; b < HT_BANKS; b++) {
        const HashTable *ht = ctx->banks[b];
        int slots = ht_total_slots(ht);
        double load = slots ? (double)ht->count / (double)slots : 0.0;
        printf("  %-4d  %-8d  %-8d  %6.2f%%\n",
               b, ht->count, slots, load * 100.0);
        total_entries += ht->count;
        total_slots   += slots;
        total_occ     += ht_occupied_entry_bytes(ht);
        total_req     += ht_memory_usage_bytes(ht);
        total_run     += ht_runtime_memory_usage_bytes(ht);
    }
    double load = total_slots ? (double)total_entries / (double)total_slots : 0.0;
    printf("hash inserted      : %d entries\n", total_entries);
    printf("hash capacity      : %d total slots\n", total_slots);
    printf("hash load factor   : %.2f%%\n", load * 100.0);
    print_memory_usage("hash occupied", total_occ);
    print_memory_usage("hash requested", total_req);
    print_memory_usage("hash runtime usable", total_run);
}

static MatchCount collect_candidates(const MatchCtx *mctx,
                              const uint8_t *pkt, int pkt_len,
                              const Bitmap *bm, const Bitmap *vm,
                              MatchCandidate **candidates, int *candidate_cap,
                              int max_stage)
{
    MatchCount res = match_scan(mctx, pkt, pkt_len, bm, vm,
                                 *candidates, *candidate_cap, max_stage);

    while (res.nc > *candidate_cap) {
        *candidate_cap = res.nc;
        *candidates = realloc(*candidates,
                              (size_t)*candidate_cap * sizeof(MatchCandidate));
        res = match_scan(mctx, pkt, pkt_len, bm, vm,
                         *candidates, *candidate_cap, max_stage);
    }

    return res;
}

int main(int argc, char *argv[])
{
    const char *rule_file = (argc > 1) ? argv[1] : "rule.txt";
    const char *pcap_file = (argc > 2) ? argv[2] : NULL;
    int max_stage = (argc > 3) ? atoi(argv[3]) : 2;
    int verbose = (argc > 4) ? atoi(argv[4]) : 1;

    if (max_stage < 1)
        max_stage = 1;

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
    SingletonResult *sr = singleton_build(rs, max_stage);
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
    Bitmap* bm_arr = malloc((size_t)max_stage * sizeof(Bitmap));
    Bitmap* bm_verifier_arr = (max_stage > 1)
                            ? malloc((size_t)(max_stage - 1) * sizeof(Bitmap))
                            : NULL;
    for (int i=0; i < (max_stage-1); i ++)
        bitmap_clear(bm_verifier_arr + i);
    for (int i=0; i < max_stage; i ++)
        bitmap_clear(bm_arr + i);

    uint8_t *min_stage_at_gram = malloc(BITMAP_BITS);
    memset(min_stage_at_gram, 0xff, BITMAP_BITS);
    for (int i = 0; i < sr->count; i++) {
        uint32_t gidx = bitmap_idx(sr->assigns[i].gram);
        int s = sr->assigns[i].stage;
        if (s < min_stage_at_gram[gidx])
            min_stage_at_gram[gidx] = (uint8_t)(s > 255 ? 255 : s);
    }

    for (int i = 0; i < sr->count; i++) {
        uint8_t* gram = sr->assigns[i].gram;
        int stage = sr->assigns[i].stage;
        uint32_t gidx = bitmap_idx(gram);
        bitmap_set_gram(bm_arr, gram);

        for (int cur_stage = 1; cur_stage < stage; cur_stage++) {
            if (min_stage_at_gram[gidx] > cur_stage) {
                Bitmap* current_verifier = bm_verifier_arr + (cur_stage-1);
                bitmap_set_gram(current_verifier, gram);
            }

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
    free(min_stage_at_gram);


    int verify_ok = 1;
    for (int i = 0; i < sr->count; i++) {
        if (!bitmap_test_gram(bm_arr, sr->assigns[i].gram)) {
            fprintf(stderr, "bitmap verify FAIL rule_id=%d\n", sr->assigns[i].rule_id);
            verify_ok = 0;
        }
    }

    int stage1_bits_set = bitmap_count_bits(bm_arr);
    int stage_bits_total = stage1_bits_set;
    int verifier_bits_total = 0;

    for (int i = 1; i < max_stage; i++)
        stage_bits_total += bitmap_count_bits(bm_arr + i);
    for (int i = 0; i < max_stage - 1; i++)
        verifier_bits_total += bitmap_count_bits(bm_verifier_arr + i);

    bool ms_verify_res = verify_ms_bitmap(bm_arr, bm_verifier_arr, sr);

    printf("stage-1 grams       : %d\n", stage1_bits_set);
    for (int i = 1; i < max_stage; i++)
        printf("stage-%d grams       : %d\n", i + 1, bitmap_count_bits(bm_arr + i));
    for (int i = 0; i < max_stage - 1; i++)
        printf("verify-%d grams      : %d\n", i + 1, bitmap_count_bits(bm_verifier_arr + i));
    printf("bitmap grams total  : %d\n", stage_bits_total + verifier_bits_total);
    printf("bitmap size         : %d bytes per bitmap (32KB)\n", (int)BITMAP_BYTES);
    printf("bitmap size total   : %zu bytes total\n",
           ((size_t)max_stage + (size_t)(max_stage - 1)) * sizeof(Bitmap));
    printf("verify              : %s\n", verify_ok ? "OK" : "FAIL");
    printf("bitmap verify       : %s\n", ms_verify_res ? "OK" : "FAIL");

    printf("\n=== matching stage ===\n");
    MatchCtx        mctx;
    int             candidate_cap = 1024;
    MatchCandidate *candidates = malloc((size_t)candidate_cap * sizeof(MatchCandidate));
    MatchResult     matches[256];
    match_init(&mctx, sr);

    size_t stage_bitmap_bytes = (size_t)max_stage * sizeof(Bitmap);
    size_t verifier_bitmap_bytes = (size_t)(max_stage - 1) * sizeof(Bitmap);
    size_t bitmap_bytes = stage_bitmap_bytes + verifier_bitmap_bytes;
    size_t stage_bitmap_runtime_bytes = allocation_usable_bytes(bm_arr);
    size_t verifier_bitmap_runtime_bytes = allocation_usable_bytes(bm_verifier_arr);
    size_t bitmap_runtime_bytes = stage_bitmap_runtime_bytes + verifier_bitmap_runtime_bytes;
    size_t hash_table_bytes = 0, hash_table_runtime_bytes = 0;
    for (int b = 0; b < HT_BANKS; b++) {
        hash_table_bytes         += ht_memory_usage_bytes(mctx.banks[b]);
        hash_table_runtime_bytes += ht_runtime_memory_usage_bytes(mctx.banks[b]);
    }

    printf("\n=== memory usage ===\n");
    print_memory_usage("stage requested", stage_bitmap_bytes);
    print_memory_usage("stage runtime usable", stage_bitmap_runtime_bytes);
    print_memory_usage("verifier requested", verifier_bitmap_bytes);
    print_memory_usage("verifier runtime usable", verifier_bitmap_runtime_bytes);
    print_memory_usage("bitmap requested", bitmap_bytes);
    print_memory_usage("bitmap runtime usable", bitmap_runtime_bytes);
    print_hash_table_usage(&mctx);
    print_memory_usage("requested total", bitmap_bytes + hash_table_bytes);
    print_memory_usage("runtime usable total", bitmap_runtime_bytes + hash_table_runtime_bytes);
    printf("runtime usable uses malloc_usable_size(); allocator metadata/RSS is not included\n");

    if (pcap_file) {
        PcapReader *pr = pcap_open(pcap_file);
        if (!pr) {
            fprintf(stderr, "failed to open pcap: %s\n", pcap_file);
        } else {
            printf("pcap             : %s\n", pcap_file);
            PcapFrame frame;
            int n_frames = 0, n_parsed = 0, n_matched_pkts = 0;
            int n_bm_pkts = 0;
            int n_exact_pkts = 0;
            int bitmap_hits_gram_cnt = 0, total_ngram_cnt = 0;
            StageStat agg_stage[MATCH_MAX_STAGES] = {0};
            int agg_bank_lookups[HT_BANKS] = {0}, agg_bank_hits[HT_BANKS] = {0};
        StageStat agg_ht = {0}, agg_cand = {0}, agg_exact = {0}, agg_pom = {0};

            typedef struct { int frame; int ids[256]; int n; } PmRecord;
            PmRecord *pm_log = malloc(16384 * sizeof(PmRecord));
            int pm_log_cnt = 0;

            while (pcap_next(pr, &frame)) {
                n_frames++;
                Packet pkt;
                if (packet_parse(frame.data, frame.caplen, &pkt) < 0
                    || pkt.payload_len == 0) {
                    pcap_frame_free(&frame);
                    continue;
                }
                n_parsed++;

                total_ngram_cnt += pkt.payload_len - N + 1;

                uint8_t folded[65536];
                size_t flen = pkt.payload_len < sizeof(folded) ? pkt.payload_len : sizeof(folded);
                for (size_t fi = 0; fi < flen; fi++) {
                    uint8_t b = pkt.payload[fi];
                    folded[fi] = (b >= 0x41 && b <= 0x5A) ? b | 0x20 : b;
                }

                MatchCount mc = collect_candidates(&mctx, folded, (int)flen,
                                            bm_arr, bm_verifier_arr,
                                            &candidates, &candidate_cap, max_stage);
                if (mc.nc > 0) n_bm_pkts++;
                if (mc.ngram_hit > 0) bitmap_hits_gram_cnt += mc.ngram_hit;
                for (int si = 0; si < mc.n_stages; si++) {
                    agg_stage[si].total += mc.stage[si].total;
                    agg_stage[si].hit   += mc.stage[si].hit;
                }
                agg_ht.total   += mc.ht_total;
                agg_ht.hit     += mc.ht_hit;
                agg_cand.total += mc.cand_total;
                agg_cand.hit   += mc.cand_hit;
                for (int bi = 0; bi < HT_BANKS; bi++) {
                    agg_bank_lookups[bi] += mc.bank_lookups[bi];
                    agg_bank_hits[bi]    += mc.bank_hits[bi];
                }

                int nm = exact_match(folded, (int)flen,
                                     candidates, mc.nc,
                                     rs, matches, 256);
                if (nm > 0) n_exact_pkts++;
                agg_exact.total += mc.nc;
                agg_exact.hit   += nm;

                MatchResult filtered[256];
                int nf = port_offset_match(matches, nm, rs, &pkt, filtered, 256);
                agg_pom.total += nm;
                agg_pom.hit   += nf;
                priority_sort(filtered, nf, rs);
                if (nf > 0) {
                    n_matched_pkts++;
                    if (pm_log_cnt < 16384) {
                        PmRecord *rec = &pm_log[pm_log_cnt++];
                        rec->frame = n_frames;
                        rec->n = nf < 256 ? nf : 256;
                        for (int j = 0; j < rec->n; j++)
                            rec->ids[j] = filtered[j].rule_id;
                    }
                }
                
                if (verbose > 1) {
                    for (int j = 0; j < nf; j++) {
                        printf("  [ALERT] frame=%-5d  rule=%-4d  anchor=%-4d  pattern=%30s\n",
                            n_frames, filtered[j].rule_id, filtered[j].anchor, rs->rules[filtered[j].rule_id].pattern);
                        printf("detected pattern: \"%.60s\"\n\n", pkt.payload);
                    }
                }
                pcap_frame_free(&frame);
            }

            printf("frames total     : %6d\n", n_frames);
            printf("frames parsed    : %6d  (IPv4/IPv6 TCP/UDP/ICMP with payload)\n", n_parsed);
            printf("bitmap hit pkts  : %6d / %8d  (%.1f%%)\n",
                   n_bm_pkts, n_parsed,
                   n_parsed ? 100.0 * n_bm_pkts / n_parsed : 0.0);
            printf("bitmap hit grams : %6d / %8d  (%.1f%%)\n",
                   bitmap_hits_gram_cnt, total_ngram_cnt,
                   total_ngram_cnt ? 100.0 * bitmap_hits_gram_cnt / total_ngram_cnt : 0.0);
            printf("exact match pkts : %6d / %8d  (%.1f%%)\n",
                   n_exact_pkts, n_parsed,
                   n_parsed ? 100.0 * n_exact_pkts / n_parsed : 0.0);
            printf("matched packets  : %6d / %8d  (%.1f%%)\n",
                   n_matched_pkts, n_parsed,
                   n_parsed ? 100.0 * n_matched_pkts / n_parsed : 0.0);

            printf("\n=== per-stage gram filter ===\n");
            printf("%-10s  %12s  %12s  %12s  %7s\n",
                   "stage", "total", "hit", "miss", "pass%");
            for (int si = 0; si < max_stage && si < MATCH_MAX_STAGES; si++) {
                int t = agg_stage[si].total;
                int h = agg_stage[si].hit;
                printf("bitmap-%-3d  %12d  %12d  %12d  %6.2f%%\n",
                       si + 1, t, h, t - h, t ? 100.0 * h / t : 0.0);
            }
            printf("%-10s  %12d  %12d  %12d  %6.2f%%\n",
                   "hashtable", agg_ht.total, agg_ht.hit, agg_ht.total - agg_ht.hit,
                   agg_ht.total ? 100.0 * agg_ht.hit / agg_ht.total : 0.0);
            printf("%-10s  %12d  %12d  %12d  %6.2f%%\n",
                   "candidate", agg_cand.total, agg_cand.hit, agg_cand.total - agg_cand.hit,
                   agg_cand.total ? 100.0 * agg_cand.hit / agg_cand.total : 0.0);
            printf("%-10s  %12d  %12d  %12d  %6.2f%%\n",
                   "exact", agg_exact.total, agg_exact.hit, agg_exact.total - agg_exact.hit,
                   agg_exact.total ? 100.0 * agg_exact.hit / agg_exact.total : 0.0);
            printf("%-10s  %12d  %12d  %12d  %6.2f%%\n",
                   "pom", agg_pom.total, agg_pom.hit, agg_pom.total - agg_pom.hit,
                   agg_pom.total ? 100.0 * agg_pom.hit / agg_pom.total : 0.0);

            printf("\n=== hashtable bank traffic ===\n");
            printf("%-4s  %12s  %12s  %7s\n", "bank", "lookups", "hits", "share%");
            for (int bi = 0; bi < HT_BANKS; bi++) {
                printf("%-4d  %12d  %12d  %6.2f%%\n",
                       bi, agg_bank_lookups[bi], agg_bank_hits[bi],
                       agg_ht.total ? 100.0 * agg_bank_lookups[bi] / agg_ht.total : 0.0);
            }

            if (verbose > 1) {
                printf("\n=== pm output ===\n");
                printf("%-8s  %s\n", "frame", "rule ids");
                for (int i = 0; i < pm_log_cnt; i++) {
                    printf("%-8d ", pm_log[i].frame);
                    for (int j = 0; j < pm_log[i].n; j++)
                        printf("%s%d", j ? " " : "", pm_log[i].ids[j]);
                    printf("\n");
                }
                free(pm_log);
                pcap_close(pr);
            }
        }
    } else {
        int fn = 0, total_bm = 0, total_exact = 0;
        StageStat agg_stage[MATCH_MAX_STAGES] = {0};
        int agg_bank_lookups[HT_BANKS] = {0}, agg_bank_hits[HT_BANKS] = {0};
        StageStat agg_ht = {0}, agg_cand = {0}, agg_exact = {0};
        for (int i = 0; i < rs->count; i++) {
            const Rule *r = &rs->rules[i];
            if (r->pat_len < 3) continue;

            MatchCount mc = collect_candidates(&mctx, (const uint8_t *)r->pattern, r->pat_len,
                                        bm_arr, bm_verifier_arr,
                                        &candidates, &candidate_cap, max_stage);
            total_bm += mc.nc;
            for (int si = 0; si < mc.n_stages; si++) {
                agg_stage[si].total += mc.stage[si].total;
                agg_stage[si].hit   += mc.stage[si].hit;
            }
            agg_ht.total   += mc.ht_total;
            agg_ht.hit     += mc.ht_hit;
            agg_cand.total += mc.cand_total;
            agg_cand.hit   += mc.cand_hit;
            for (int bi = 0; bi < HT_BANKS; bi++) {
                agg_bank_lookups[bi] += mc.bank_lookups[bi];
                agg_bank_hits[bi]    += mc.bank_hits[bi];
            }

            int nm = exact_match((const uint8_t *)r->pattern, r->pat_len,
                                 candidates, mc.nc,
                                 rs, matches, 256);
            total_exact += nm;
            agg_exact.total += mc.nc;
            agg_exact.hit   += nm;

            int found = 0;
            for (int j = 0; j < nm; j++)
                if (matches[j].rule_id == r->id) { found = 1; break; }
            if (!found) fn++;
        }
        printf("rules scanned   : %d\n", rs->count);
        printf("bitmap hits     : %d  (potential match candidates)\n", total_bm);
        printf("exact matches   : %d\n", total_exact);
        printf("false negatives : %d\n", fn);

        printf("\n=== per-stage gram filter ===\n");
        printf("%-10s  %12s  %12s  %12s  %7s\n",
               "stage", "total", "hit", "miss", "pass%");
        for (int si = 0; si < max_stage && si < MATCH_MAX_STAGES; si++) {
            int t = agg_stage[si].total;
            int h = agg_stage[si].hit;
            printf("bitmap-%-3d  %12d  %12d  %12d  %6.2f%%\n",
                   si + 1, t, h, t - h, t ? 100.0 * h / t : 0.0);
        }
        printf("%-10s  %12d  %12d  %12d  %6.2f%%\n",
               "hashtable", agg_ht.total, agg_ht.hit, agg_ht.total - agg_ht.hit,
               agg_ht.total ? 100.0 * agg_ht.hit / agg_ht.total : 0.0);
        printf("%-10s  %12d  %12d  %12d  %6.2f%%\n",
               "candidate", agg_cand.total, agg_cand.hit, agg_cand.total - agg_cand.hit,
               agg_cand.total ? 100.0 * agg_cand.hit / agg_cand.total : 0.0);
        printf("%-10s  %12d  %12d  %12d  %6.2f%%\n",
               "exact", agg_exact.total, agg_exact.hit, agg_exact.total - agg_exact.hit,
               agg_exact.total ? 100.0 * agg_exact.hit / agg_exact.total : 0.0);

        printf("\n=== hashtable bank traffic ===\n");
        printf("%-4s  %12s  %12s  %7s\n", "bank", "lookups", "hits", "share%");
        for (int bi = 0; bi < HT_BANKS; bi++) {
            printf("%-4d  %12d  %12d  %6.2f%%\n",
                   bi, agg_bank_lookups[bi], agg_bank_hits[bi],
                   agg_ht.total ? 100.0 * agg_bank_lookups[bi] / agg_ht.total : 0.0);
        }

        printf("\nSample self-matches (first 5 eligible rules):\n");
        printf("  %-6s  %-6s  %-8s  %s\n", "ruleid", "anchor", "gram", "pattern (first 20 bytes)");
        int shown = 0;
        for (int i = 0; i < rs->count && shown < 5; i++) {
            const Rule *r = &rs->rules[i];
            if (r->pat_len < 3) continue;
            MatchCount mc = collect_candidates(&mctx, (const uint8_t *)r->pattern, r->pat_len,
                                        bm_arr, bm_verifier_arr,
                                        &candidates, &candidate_cap, max_stage);
            int nm = exact_match((const uint8_t *)r->pattern, r->pat_len,
                                 candidates, mc.nc,
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

    free(candidates);
    free(bm_arr);
    free(bm_verifier_arr);
    singleton_free(sr);
    rules_free(rs);
    return 0;
}
