
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rule_loader.h"
#include "singleton.h"
#include "bitmap.h"

#define BITMAP_LINES          512
#define GHT_ENTRY_BYTES       16

#define BLOOM_BYTES           (32 * 1024)   /* 262144 bits */
#define BLOOM_BITS            (BLOOM_BYTES * 8)
#define BLOOM_K               3
#define BLOOM_C1              0x9E3779B97F4A7C15ULL
#define BLOOM_C2              0xC2B2AE3D27D4EB4FULL
#define MAX_STAGE             2          /* HW supports a single next-gram check (bm1). */

/* -------------------------------------------------------------------------
 * GHT entry — one per (gram, rule) pair the kernel uses at runtime.
 * ------------------------------------------------------------------------- */
typedef struct {
    uint32_t gram;
    uint16_t rule_id;
    int8_t   pre;
    int8_t   post;
    uint8_t  len;
    bool     stage2;
    uint32_t next_gram_key;
    uint32_t anchor_gram24;
    bool     is_first;
    bool     is_last;
} GhtEntry;

static GhtEntry *ght_entries = NULL;
static int       ght_count   = 0;
static uint8_t   bloom_bits[BLOOM_BYTES];

/* Multiply-shift (Fibonacci) double hash → Kirsch-Mitzenmacher k positions.
 * Mirror this exactly in GramMatcher.bsv::bloomHash. */
static void bloom_probe(uint64_t key, uint32_t pos[BLOOM_K])
{
    uint64_t a  = key * BLOOM_C1;            /* 64-bit wrap */
    uint64_t b  = key * BLOOM_C2;
    uint32_t h1 = (uint32_t)(a >> 32);
    uint32_t h2 = ((uint32_t)(b >> 32)) | 1u;
    for (int i = 0; i < BLOOM_K; i++)
        pos[i] = (h1 + (uint32_t)i * h2) & (BLOOM_BITS - 1);   /* % 2^18 */
}

/* Add one bloom membership per unique cuckoo key (chain head = is_first), using
 * the same key the HW GramMatcher tests: (gram<<18)|next_gram_key. */
static void build_bloom(void)
{
    memset(bloom_bits, 0, sizeof(bloom_bits));
    int unique = 0;
    for (int i = 0; i < ght_count; i++) {
        if (!ght_entries[i].is_first) continue;
        uint64_t key = ((uint64_t)ght_entries[i].gram << 18)
                     | (ght_entries[i].next_gram_key & 0x3FFFFu);
        uint32_t pos[BLOOM_K];
        bloom_probe(key, pos);
        for (int j = 0; j < BLOOM_K; j++)
            bloom_bits[pos[j] >> 3] |= (uint8_t)(1u << (pos[j] & 7));
        unique++;
    }
    fprintf(stderr, "bloom: %d unique keys into %d-bit filter (k=%d, mult-shift)\n",
            unique, BLOOM_BITS, BLOOM_K);
}

static int cmp_ght_by_htkey(const void *a, const void *b)
{
    const GhtEntry *x = (const GhtEntry *)a;
    const GhtEntry *y = (const GhtEntry *)b;
    uint64_t ka = ((uint64_t)x->gram << 18) | (x->next_gram_key & 0x3FFFFu);
    uint64_t kb = ((uint64_t)y->gram << 18) | (y->next_gram_key & 0x3FFFFu);
    return (ka < kb) ? -1 : (ka > kb);
}

static uint32_t make_gram24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

/* -------------------------------------------------------------------------
 * Globals — the DB blob is small enough to assemble in static buffers.
 * ------------------------------------------------------------------------- */
static Bitmap   bm0_s1, bm0_s2, bm1;
static uint8_t  patterns[MAX_RULES][64];
static uint64_t rule_constraint[MAX_RULES];   /* one 64-bit slot per ruleId */

static RuleSet *g_rs = NULL;

static const Rule *find_rule(int rule_id)
{
    for (int i = 0; i < g_rs->count; i++)
        if (g_rs->rules[i].id == rule_id)
            return &g_rs->rules[i];
    return NULL;
}

/* -------------------------------------------------------------------------
 * Convert SingletonResult into kernel GHT entries.
 *   bm0_s1 / bm0_s2 split lets the kernel decide before the cuckoo lookup
 *   whether bm1 must be checked first.  Stage-2 rules add a bm1 bit on the
 *   gram immediately after the anchor.
 * ------------------------------------------------------------------------- */
static void build_ght_from_singleton(const SingletonResult *sr)
{
    bitmap_clear(&bm0_s1);
    bitmap_clear(&bm0_s2);
    bitmap_clear(&bm1);

    ght_entries = malloc((size_t)sr->count * sizeof(GhtEntry));
    ght_count   = 0;

    int stage2_rules = 0;
    for (int i = 0; i < sr->count; i++) {
        const GramAssign *a  = &sr->assigns[i];
        const Rule       *r  = find_rule(a->rule_id);
        if (!r) continue;

        uint32_t sg       = a->gram_idx;
        bool     stage2   = (a->stage == 2);
        uint32_t next_key = 0;

        bitmap_set(stage2 ? &bm0_s2 : &bm0_s1, sg);
        if (stage2) {
            next_key = bitmap_idx(a->next_grams);
            bitmap_set(&bm1, next_key);
            stage2_rules++;
        }

        ght_entries[ght_count++] = (GhtEntry){
            .gram          = sg,
            .rule_id       = (uint16_t)a->rule_id,
            .pre           = (int8_t)a->pre_offset,
            .post          = (int8_t)a->post_offset,
            .len           = (uint8_t)r->pat_len,
            .stage2        = stage2,
            .next_gram_key = next_key,
            .anchor_gram24 = make_gram24(a->gram),
        };
    }
    fprintf(stderr, "singleton: stage2 rules = %d / %d\n",
            stage2_rules, ght_count);
    if (sr->uncovered)
        fprintf(stderr, "singleton: %d rule(s) dropped\n", sr->uncovered);

    /* Group entries by composite HT key (gram, next_gram_key) so chain-follow
     * walks contiguous slots per cuckoo bucket; mark is_first / is_last per
     * chain to terminate the walk.  Boundaries break when either gram or
     * next_gram_key changes. */
    qsort(ght_entries, ght_count, sizeof(GhtEntry), cmp_ght_by_htkey);
    int unique_grams = 0, shared_grams = 0, shared_rules = 0, max_chain = 0;
    int cur_chain = 0;
    for (int i = 0; i < ght_count; i++) {
        bool same_prev = (i > 0)
            && (ght_entries[i].gram == ght_entries[i - 1].gram)
            && (ght_entries[i].next_gram_key == ght_entries[i - 1].next_gram_key);
        bool same_next = (i < ght_count - 1)
            && (ght_entries[i].gram == ght_entries[i + 1].gram)
            && (ght_entries[i].next_gram_key == ght_entries[i + 1].next_gram_key);
        ght_entries[i].is_first = !same_prev;
        ght_entries[i].is_last  = !same_next;
        cur_chain++;
        if (ght_entries[i].is_last) {
            if (cur_chain == 1)        unique_grams++;
            else { shared_grams++; shared_rules += cur_chain; }
            if (cur_chain > max_chain) max_chain = cur_chain;
            cur_chain = 0;
        }
    }
    fprintf(stderr,
            "singleton: unique_grams (1:1) = %d  shared_grams (1:N) = %d "
            "(avg %.2f rules/gram, max chain = %d)\n",
            unique_grams, shared_grams,
            shared_grams ? (double)shared_rules / shared_grams : 0.0,
            max_chain);
}

/* rule_loader already case-folded; just copy into the indexed slot. */
static void build_patterns(void)
{
    memset(patterns, 0, sizeof(patterns));
    for (int i = 0; i < g_rs->count; i++) {
        const Rule *r = &g_rs->rules[i];
        if (r->id < 0 || r->id >= MAX_RULES) continue;
        int n = r->pat_len > 64 ? 64 : r->pat_len;
        for (int j = 0; j < n; j++)
            patterns[r->id][j] = (uint8_t)r->pattern[j];
    }
}

static void build_portloc(void)
{
    memset(rule_constraint, 0, sizeof(rule_constraint));

    for (int i = 0; i < g_rs->count; i++) {
        const Rule *r = &g_rs->rules[i];
        if (r->id < 0 || r->id >= MAX_RULES) continue;

        uint64_t e = 1ull;                                         /* valid    */
        e |= ((uint64_t)(r->proto & 0xFF))                << 1;    /* proto    */
        e |= ((uint64_t)(r->is_request == 1 ? 1u : 0u))   << 9;    /* isReq    */
        e |= ((uint64_t)(r->port & 0xFFFF))               << 10;   /* port     */
        e |= ((uint64_t)(r->offset_mode & 0x3))           << 26;   /* offMode  */
        e |= ((uint64_t)((uint32_t)r->offset_val & 0xFFFFFu)) << 28; /* offVal */
        e |= ((uint64_t)(r->icmp_type & 0xFF))            << 48;   /* icmpType */
        e |= ((uint64_t)(r->icmp_code & 0xFF))            << 56;   /* icmpCode */
        rule_constraint[r->id] = e;
    }
}

/* -------------------------------------------------------------------------
 * DB blob assembly
 * ------------------------------------------------------------------------- */
static void write_le32(uint8_t *p, uint32_t v)
{
    p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24;
}

static void write_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* Kernel table capacity (5k-rule build).  Must match the BSV parameters:
 *   GramMatcher.bsv       NChainEntries = 8192, ChainIdxBits = 13
 *   ExactPatternTable.bsv 16 tiles x 512 deep  = 8192 slots
 *   PortOffsetMatcher.bsv memorySize    = 8192
 *   Priority.bsv          memorySize    = 8192
 * Rule ids at or above this alias onto lower slots in hardware (the tables are
 * indexed by the low bits of ruleId), so refuse to emit a blob the kernel
 * cannot hold rather than producing silently wrong matches. */
#define KERNEL_RULE_SLOTS 8192

static int write_db(const char *path)
{
    uint32_t bm_each      = BITMAP_BYTES;          /* 32KB */
    uint32_t ght_off      = 64 + bm_each * 3;
    uint32_t ght_bytes    = (uint32_t)ght_count * GHT_ENTRY_BYTES;
    uint32_t ruledb_off   = (ght_off + ght_bytes + 63) & ~63u;
    /* Pattern table is indexed by rule.id, which may be sparse / exceed
     * g_rs->count.  Size and report the slot count by max_rule_id+1 so
     * the kernel loads every populated slot. */
    int max_rule_id = -1;
    for (int i = 0; i < g_rs->count; i++)
        if (g_rs->rules[i].id > max_rule_id) max_rule_id = g_rs->rules[i].id;
    uint32_t pat_slots    = (uint32_t)(max_rule_id + 1);
    if (pat_slots > KERNEL_RULE_SLOTS) {
        fprintf(stderr, "ERROR: max rule id %d needs %u pattern slots, but the "
                        "kernel holds %d (5k-rule build)\n",
                max_rule_id, pat_slots, KERNEL_RULE_SLOTS);
        return -1;
    }
    if (ght_count > KERNEL_RULE_SLOTS) {
        fprintf(stderr, "ERROR: %d GHT entries exceed the kernel chain table "
                        "(%d entries, 5k-rule build)\n",
                ght_count, KERNEL_RULE_SLOTS);
        return -1;
    }
    uint32_t ruledb_bytes = pat_slots * 64;
    uint32_t portloc_off  = (ruledb_off + ruledb_bytes + 63) & ~63u;

    /* Rule-indexed constraint table: one 64-bit slot per rule slot. */
    uint32_t portloc_bytes = ((pat_slots * 8) + 63) & ~63u;

    uint32_t prioloc_off   = (portloc_off + portloc_bytes + 63) & ~63u;
    /* Indexed by rule id, like portloc: size by pat_slots (max id + 1), which is
     * also the entry count DataLoader reads (header "pat").  Sizing by the rule
     * count left the section a word short whenever max id + 1 did not fit (count a
     * multiple of 64, or sparse ids): the last priorities landed in the bloom
     * region and the loader, one word short, hung waiting for bloom data. */
    uint32_t prioloc_bytes = ((pat_slots + 63) >> 6) << 6;
    uint32_t bloom_off     = (prioloc_off + prioloc_bytes + 63) & ~63u;
    uint32_t bloom_bytes   = BLOOM_BYTES;
    uint32_t total         = bloom_off + bloom_bytes;

    uint8_t *blob = calloc(1, total);
    if (!blob) { fputs("OOM\n", stderr); return -1; }

    /* --- header (64B) --- */
    write_le32(blob + 0,  0xDB600D01u);
    write_le32(blob + 4,  1u);
    write_le32(blob + 8,  BITMAP_LINES);
    write_le32(blob + 12, (uint32_t)ght_count);
    write_le32(blob + 16, pat_slots);
    write_le32(blob + 20, ruledb_off);
    write_le32(blob + 24, portloc_off);
    write_le32(blob + 28, prioloc_off);
    write_le32(blob + 32, bloom_off);

    /* --- bm0_s1, bm0_s2, bm1 --- */
    memcpy(blob + 64,                bm0_s1.data, bm_each);
    memcpy(blob + 64 +     bm_each,  bm0_s2.data, bm_each);
    memcpy(blob + 64 + 2 * bm_each,  bm1.data,    bm_each);

    /* --- GHT entries --- */
    for (int i = 0; i < ght_count; i++) {
        uint8_t *e = blob + ght_off + i * GHT_ENTRY_BYTES;
        write_le32(e, ght_entries[i].gram);
        e[4] = ght_entries[i].rule_id & 0xFF;
        e[5] = ght_entries[i].rule_id >> 8;
        e[6] = (uint8_t)ght_entries[i].pre;
        e[7] = (uint8_t)ght_entries[i].post;
        e[8] = ght_entries[i].len;
        uint32_t nk = ght_entries[i].next_gram_key & 0x3FFFFu;
        e[9]  = (uint8_t)((ght_entries[i].stage2 ? 1u : 0u) | ((nk & 0x7Fu) << 1));
        e[10] = (uint8_t)((nk >> 7) & 0xFFu);
        e[11] = (uint8_t)((nk >> 15) & 0x07u);
        uint32_t ag = ght_entries[i].anchor_gram24 & 0xFFFFFFu;
        e[11] |= (uint8_t)((ag & 0x1Fu) << 3);
        e[12]  = (uint8_t)((ag >> 5)  & 0xFFu);
        e[13]  = (uint8_t)((ag >> 13) & 0xFFu);
        e[14]  = (uint8_t)((ag >> 21) & 0x07u);
        e[15]  = (uint8_t)((ght_entries[i].is_first ? 1u : 0u)
                         | (ght_entries[i].is_last  ? 2u : 0u));
    }

    /* --- patterns --- */
    for (int i = 0; i < g_rs->count; i++) {
        const Rule *r = &g_rs->rules[i];
        if (r->id < 0 || r->id >= MAX_RULES) continue;
        uint8_t *dst = blob + ruledb_off + (uint32_t)r->id * 64;
        if ((size_t)(dst - blob) + 64 <= total)
            memcpy(dst, patterns[r->id], 64);
    }

    /* --- portloc: rule-indexed constraint table (8B/rule by ruleId) --- */
    for (uint32_t i = 0; i < pat_slots; i++)
        write_le64(blob + portloc_off + i * 8, rule_constraint[i]);

    /* --- priority table: rule_loader already stored Rule.priority. --- */
    for (int i = 0; i < g_rs->count; i++) {
        const Rule *r = &g_rs->rules[i];
        if (r->id < 0 || r->id >= MAX_RULES) continue;
        if (prioloc_off + (uint32_t)r->id < total)
            blob[prioloc_off + (uint32_t)r->id] = (uint8_t)(r->priority & 0x03);
    }

    /* --- bloom filter --- byte p>>3 holds bit p&7; little-endian layout matches
     * HW: 512-bit line k holds 64-bit words[8k..8k+7], word bit = pos[5:0]. */
    memcpy(blob + bloom_off, bloom_bits, bloom_bytes);

    FILE *fout = fopen(path, "wb");
    if (!fout) { perror(path); free(blob); return -1; }
    fwrite(blob, 1, total, fout);
    fclose(fout);
    free(blob);

    printf("rules=%d  ght_entries=%d  total=%u bytes\n",
           g_rs->count, ght_count, total);
    printf("  bm0_s1   @ 0x%06X  (%u KB)\n", 64, bm_each / 1024);
    printf("  bm0_s2   @ 0x%06X  (%u KB)\n", 64 + bm_each, bm_each / 1024);
    printf("  bm1      @ 0x%06X  (%u KB)\n", 64 + 2 * bm_each, bm_each / 1024);
    printf("  ght      @ 0x%06X  (%u entries × %dB)\n",
           ght_off, ght_count, GHT_ENTRY_BYTES);
    printf("  patterns @ 0x%06X  (%u entries × 64B)\n", ruledb_off, g_rs->count);
    printf("  portloc  @ 0x%06X  (%u B)\n", portloc_off, portloc_bytes);
    printf("  priority @ 0x%06X  (%u B)\n", prioloc_off, prioloc_bytes);
    printf("  bloom    @ 0x%06X  (%u B, k=%d)\n", bloom_off, bloom_bytes, BLOOM_K);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rule_file> <output_db.bin>\n", argv[0]);
        return 1;
    }

    g_rs = rules_load(argv[1]);
    if (!g_rs)             { perror(argv[1]); return 1; }
    if (g_rs->count == 0)  { fputs("no rules parsed\n", stderr); rules_free(g_rs); return 1; }

    SingletonResult *sr = singleton_build(g_rs, MAX_STAGE);
    if (!sr) { fputs("singleton_build failed\n", stderr); rules_free(g_rs); return 1; }

    build_ght_from_singleton(sr);
    build_patterns();
    build_portloc();
    build_bloom();

    int ret = write_db(argv[2]);

    singleton_free(sr);
    rules_free(g_rs);
    free(ght_entries);
    return ret;
}
