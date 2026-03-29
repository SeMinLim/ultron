#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "rule_loader.h"
#include "ngram_extract.h"
#include "singleton.h"
#include "bitmap.h"

#define N 3

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
    const char *filename = (argc > 1) ? argv[1] : "rule.txt";

    RuleSet *rs = rules_load(filename);
    if (!rs) {
        fprintf(stderr, "failed to load: %s\n", filename);
        return 1;
    }

    /* rule stats */
    int total_bytes = 0, min_len = 999999, max_len = 0, total_grams = 0;
    for (int i = 0; i < rs->count; i++) {
        int l = rs->rules[i].pat_len;
        total_bytes += l;
        if (l < min_len) min_len = l;
        if (l > max_len) max_len = l;
        if (l >= N) total_grams += l - N + 1;
    }

    printf("file       : %s\n", filename);
    printf("rules      : %d\n", rs->count);
    printf("pat min    : %d bytes\n", min_len);
    printf("pat max    : %d bytes\n", max_len);
    printf("pat avg    : %.1f bytes\n", rs->count ? (double)total_bytes / rs->count : 0.0);
    printf("n          : %d\n", N);
    printf("total grams: %d\n", total_grams);

    /* unique ngrams across all rules */
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

    /* singleton: greedy gram selection per rule */
    printf("=== singleton build ===\n");
    SingletonResult *sr = singleton_build(rs);
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

    printf("%-6s  %-10s  %-5s  %-4s  %-4s  %s\n",
           "ruleid", "gram", "pos", "pre", "post", "deg");
    printf("------  ----------  -----  ----  ----  ---\n");
    for (int i = 0; i < sr->count; i++) {
        GramAssign *a = &sr->assigns[i];
        printf("%-6d  ", a->rule_id);
        print_gram(a->gram);
        printf("%-7s  %-5d  %-4d  %-4d  %d\n",
               "", a->gram_pos, a->pre_offset, a->post_offset, a->degree);
    }

    /* bitmap: build from singleton-selected grams */
    printf("\n=== bitmap build ===\n");
    Bitmap *bm = calloc(1, sizeof(Bitmap));
    bitmap_clear(bm);

    for (int i = 0; i < sr->count; i++)
        bitmap_set_gram(bm, sr->assigns[i].gram);

    /* verify: every selected gram must hit the bitmap */
    int verify_ok = 1;
    for (int i = 0; i < sr->count; i++) {
        if (!bitmap_test_gram(bm, sr->assigns[i].gram)) {
            fprintf(stderr, "bitmap verify FAIL rule_id=%d\n", sr->assigns[i].rule_id);
            verify_ok = 0;
        }
    }

    /* count set bits to show actual unique grams in bitmap */
    int bits_set = 0;
    for (int i = 0; i < (int)BITMAP_BYTES; i++) {
        uint8_t b = bm->data[i];
        while (b) { bits_set += b & 1; b >>= 1; }
    }

    printf("grams in bitmap : %d  (unique representative grams)\n", bits_set);
    printf("bitmap size     : %d bytes (2MB)\n", (int)BITMAP_BYTES);
    printf("verify          : %s\n", verify_ok ? "OK" : "FAIL");

    free(bm);
    singleton_free(sr);
    rules_free(rs);
    return 0;
}
