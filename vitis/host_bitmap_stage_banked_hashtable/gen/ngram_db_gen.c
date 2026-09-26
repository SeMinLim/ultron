/*
 * ngram_db_gen.c — Build the kernel DB blob from a rule file.
 *
 * Rule file format (one rule per line):
 *   id=<N> protocol=<proto>[/<port>][/<dir>] offset=<val>[/small|big] pattern=<url-encoded-bytes>
 *
 * Output DB blob layout (must match hw/kernel_neo_bitmap_stage/DataLoader.bsv):
 *   [0x000000..0x000040)  64B header
 *   [0x000040..0x008040)  bitmap0 (singleton 3-grams) 512 × 64B   (32KB)
 *   [0x008040..0x010040)  bitmap1 (next-grams of stage-2 rules)   (32KB)
 *   [0x010040..        )  GHT entries     ght_count × 16B    (flat list)
 *   [ruledb_off..      )  pattern bytes   pattern_count × 64B
 *   [portloc_off..     )  port tables     see PortOffsetMatcher write methods
 *
 * GHT entry (16B):  bit-layout decoded by DataLoader.bsv::unpackRuleInfo.
 *   bits [31: 0]   gram18 (uint32, upper 14 bits 0)
 *   bits [47:32]   ruleId
 *   bits [55:48]   pre  (int8)
 *   bits [63:56]   post (int8)
 *   bits [71:64]   len  (uint8)
 *   bit  [72]      stage2 flag
 *   bits [90:73]   nextGramKey (18 bits, valid when stage2=1)
 *   bits [127:91]  reserved
 *
 * Build:
 *   cc -O2 -std=c17 -o ngram_db_gen ngram_db_gen.c
 * Usage:
 *   ngram_db_gen <rule_file> <output_db.bin>
 */

#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <limits.h>

#define MAX_RULES        16384
#define MAX_PATTERN_LEN  64
/* 18-bit gram key (matches ref/ultron/c_ref/mky_backup/bitmap.h) →
 * 2^18 = 262144 bits = 32 KB per bitmap = 512 × 64B lines. */
#define BITMAP_LINES     512
#define BITMAP_BYTES     (BITMAP_LINES * 64)
#define GHT_ENTRY_BYTES  16
#define PORTLOC_BM_LINES 128           /* per bitmap table */
#define PORTLOC_WIN_ENTRIES 1024       /* per window table */
#define PORTLOC_SMALL_ENTRIES 256      /* ipproto / icmp tables */

/* -------------------------------------------------------------------------
 * Rule representation
 * ------------------------------------------------------------------------- */
typedef enum { PLM_NONE, PLM_TCP_DST, PLM_TCP_SRC, PLM_UDP_DST, PLM_UDP_SRC,
               PLM_IPPROTO, PLM_ICMP } PlmGroup;

typedef struct {
    uint16_t id;
    uint8_t  pattern[MAX_PATTERN_LEN];
    uint8_t  pat_len;
    int8_t   pre;    /* pattern start = anchor + pre */
    int8_t   post;   /* pattern end   = anchor + post */
    PlmGroup plm_group;
    uint16_t plm_port;
    uint8_t  plm_proto;
    uint8_t  plm_icmp_type;
    uint8_t  plm_icmp_code;
    uint32_t offset_val;
    bool     is_big;
} Rule;

static Rule   rules[MAX_RULES];
static int    rule_count = 0;

/* -------------------------------------------------------------------------
 * Bitmap: 512 × 512-bit = 32768 bytes (2^18 bits).
 * key18 = {b0[5:0], b1[5:0], b2[5:0]}  (lower 6 bits of each gram byte)
 * line_addr = key18 >> 9        (9-bit line, 512 lines)
 * bit_index = key18 & 0x1FF     (9-bit bit, 512 bits per line)
 * Case-fold (A..Z → a..z) is applied first because bit 5 is inside the low 6
 * bits and would otherwise split letter pairs.
 * ------------------------------------------------------------------------- */
static uint8_t bitmap[BITMAP_BYTES];   /* bitmap0: every singleton 3-gram   */
static uint8_t bitmap1[BITMAP_BYTES];  /* bitmap1: next-grams of stage-2 rules */

#define MAX_STAGE 2  /* HW supports a single next-gram check (bitmap1). */

static uint8_t fold_case(uint8_t b)
{
    return (b >= 0x41 && b <= 0x5A) ? (b | 0x20) : b;
}

static void bitmap_set_key(uint8_t *bm, uint32_t key18)
{
    uint32_t line  = key18 >> 9;
    uint32_t bit   = key18 & 0x1FF;
    uint32_t byte_off = line * 64 + bit / 8;
    uint8_t  bit_off  = bit % 8;
    if (byte_off < BITMAP_BYTES)
        bm[byte_off] |= (1u << bit_off);
}

static void bitmap_set_gram(const uint8_t *gram3)
{
    uint32_t b0 = fold_case(gram3[0]) & 0x3F;
    uint32_t b1 = fold_case(gram3[1]) & 0x3F;
    uint32_t b2 = fold_case(gram3[2]) & 0x3F;
    bitmap_set_key(bitmap, (b0 << 12) | (b1 << 6) | b2);
}

// bitmap0 (== c_ref bm_arr[0]) must contain ONLY the selected singletons,
// not every 3-gram of every rule.  Setting every gram inflates density
// ~50x and destroys the pre-filter (99.7% pass instead of <1%).
// build_bitmap is kept as a clear-only helper; bm0 bits are set per-rule
// inside build_ght() once the singleton choice is final.
static void build_bitmap(void)
{
    memset(bitmap, 0, sizeof(bitmap));
}

/* -------------------------------------------------------------------------
 * GHT entries: one entry per (gram, ruleId) pair.
 *
 * Singleton-gram selection (ported from ref/ultron/c_ref/mky_backup):
 *   1. Per-rule dedup, build a hashtable gram -> list of rules containing it
 *   2. Seed a BFS queue with all grams whose degree == 1 (unique to one rule)
 *   3. Greedy cover: pop from the BFS queue; when empty, pick the lowest
 *      remaining degree
 *   4. Hardware constraint: the on-chip CuckooHash stores one value per key,
 *      so each selected gram covers exactly ONE rule (first uncovered rule
 *      that contained it).  Other rules that shared that gram must fall
 *      back to a different gram in a later iteration; if none remain they
 *      are logged and dropped.
 * ------------------------------------------------------------------------- */
typedef struct {
    uint32_t gram;
    uint16_t rule_id;
    int8_t   pre;
    int8_t   post;
    uint8_t  len;
    bool     stage2;        /* true iff a next-gram check is required */
    uint32_t next_gram_key; /* 21-bit key for the gram at gram_pos+3   */
} GhtEntry;

static GhtEntry ght_entries[MAX_RULES];
static int      ght_count = 0;

/* 18-bit gram key = {byte0[5:0], byte1[5:0], byte2[5:0]} on already-folded
 * bytes.  Matches the c_ref bitmap_idx and the HW CuckooHash key so the
 * bitmap, the on-chip gram table, and the singleton selection all share the
 * same gram equivalence classes. */
static uint32_t make_gram18(const uint8_t *p)
{
    return ((uint32_t)(fold_case(p[0]) & 0x3F) << 12) |
           ((uint32_t)(fold_case(p[1]) & 0x3F) <<  6) |
            (uint32_t)(fold_case(p[2]) & 0x3F);
}

#define GHT_EMPTY_GRAM 0xFFFFFFFFu

typedef struct {
    uint32_t *data;
    int       n;
    int       cap;
} GramVec;

static void gram_vec_push(GramVec *v, uint32_t g)
{
    if (v->n == v->cap) {
        v->cap  = v->cap ? v->cap * 2 : 8;
        v->data = realloc(v->data, (size_t)v->cap * sizeof(uint32_t));
    }
    v->data[v->n++] = g;
}

static bool gram_vec_has(const GramVec *v, uint32_t g)
{
    for (int i = 0; i < v->n; i++)
        if (v->data[i] == g) return true;
    return false;
}

typedef struct {
    uint32_t gram;
    int     *rule_ids;
    int      count;
    int      cap;
    int      degree;
    bool     gone;
} GramNode;

typedef struct {
    GramNode *slots;
    int       size;   /* power of 2 */
} GramHT;

static GramHT *gram_ht_new(int min_slots)
{
    int s = 1;
    while (s < min_slots * 2) s <<= 1;
    GramHT *h = malloc(sizeof *h);
    h->size   = s;
    h->slots  = malloc((size_t)s * sizeof(GramNode));
    for (int i = 0; i < s; i++) {
        h->slots[i].gram     = GHT_EMPTY_GRAM;
        h->slots[i].rule_ids = NULL;
        h->slots[i].count    = 0;
        h->slots[i].cap      = 0;
        h->slots[i].degree   = 0;
        h->slots[i].gone     = false;
    }
    return h;
}

/* Open-addressed slot lookup.  GHT_EMPTY_GRAM marks a free slot. */
static GramNode *gram_ht_slot(GramHT *h, uint32_t g)
{
    uint32_t mask = (uint32_t)(h->size - 1);
    uint32_t pos  = (g * 2654435761u) & mask;
    while (h->slots[pos].gram != GHT_EMPTY_GRAM && h->slots[pos].gram != g)
        pos = (pos + 1u) & mask;
    return &h->slots[pos];
}

static GramNode *gram_ht_find(GramHT *h, uint32_t g)
{
    GramNode *n = gram_ht_slot(h, g);
    return (n->gram == g) ? n : NULL;
}

static GramNode *gram_ht_insert(GramHT *h, uint32_t g)
{
    GramNode *n = gram_ht_slot(h, g);
    if (n->gram == GHT_EMPTY_GRAM)
        n->gram = g;
    return n;
}

static void gram_ht_add_rule(GramNode *n, int rid)
{
    if (n->count == n->cap) {
        n->cap      = n->cap ? n->cap * 2 : 4;
        n->rule_ids = realloc(n->rule_ids, (size_t)n->cap * sizeof(int));
    }
    n->rule_ids[n->count++] = rid;
    n->degree++;
}

static void gram_ht_free(GramHT *h)
{
    for (int i = 0; i < h->size; i++)
        if (h->slots[i].gram != GHT_EMPTY_GRAM)
            free(h->slots[i].rule_ids);
    free(h->slots);
    free(h);
}

/* Drain the BFS queue (degree==1 grams); otherwise scan for the lowest
   non-zero degree remaining.  Returns NULL when no gram is available. */
static GramNode *pick_next_gram(GramHT *ht,
                                uint32_t *queue, int *qhead, int qtail,
                                uint32_t *out_gram)
{
    while (*qhead < qtail) {
        uint32_t  g = queue[(*qhead)++];
        GramNode *n = gram_ht_find(ht, g);
        if (n && !n->gone && n->degree > 0) {
            *out_gram = g;
            return n;
        }
    }
    GramNode *best     = NULL;
    int       best_deg = INT_MAX;
    for (int i = 0; i < ht->size; i++) {
        GramNode *n = &ht->slots[i];
        if (n->gram == GHT_EMPTY_GRAM || n->gone || n->degree == 0) continue;
        if (n->degree < best_deg) {
            best_deg  = n->degree;
            best      = n;
            *out_gram = n->gram;
        }
    }
    return best;
}

static int gram_position_in_rule(const Rule *r, uint32_t g18)
{
    for (int i = 0; i + 2 < r->pat_len; i++)
        if (make_gram18(r->pattern + i) == g18) return i;
    return 0;
}

static void build_ght(void)
{
    int nr = rule_count;

    int est_grams = 0;
    for (int i = 0; i < nr; i++)
        if (rules[i].pat_len >= 3)
            est_grams += rules[i].pat_len - 2;

    GramHT  *ht         = gram_ht_new(est_grams + 64);
    GramVec *rule_grams = calloc((size_t)nr, sizeof(GramVec));
    int     *rule_sel   = malloc((size_t)nr * sizeof(int));
    bool    *rule_cov   = calloc((size_t)nr, sizeof(bool));
    for (int i = 0; i < nr; i++) rule_sel[i] = -1;

    /* Step 1: per-rule gram dedup + build gram -> rule list.  Grams are
     * keyed by their 21-bit equivalence class so the selection matches the
     * on-chip bitmap and CuckooHash key space exactly. */
    for (int rid = 0; rid < nr; rid++) {
        const Rule *r = &rules[rid];
        if (r->pat_len < 3) continue;
        for (int i = 0; i + 2 < r->pat_len; i++) {
            uint32_t g18 = make_gram18(r->pattern + i);
            if (gram_vec_has(&rule_grams[rid], g18)) continue;
            gram_vec_push(&rule_grams[rid], g18);
            gram_ht_add_rule(gram_ht_insert(ht, g18), rid);
        }
    }

    int n_uncov = 0;
    for (int i = 0; i < nr; i++)
        if (rules[i].pat_len >= 3) n_uncov++;

    /* Step 2: seed BFS queue with all degree==1 grams. */
    int       qcap  = est_grams * 2 + ht->size + 1;
    uint32_t *queue = malloc((size_t)qcap * sizeof(uint32_t));
    int       qhead = 0, qtail = 0;
    for (int i = 0; i < ht->size; i++) {
        GramNode *n = &ht->slots[i];
        if (n->gram != GHT_EMPTY_GRAM && n->degree == 1)
            queue[qtail++] = n->gram;
    }

    /* Step 3: greedy cover; each selected gram covers exactly one rule. */
    while (n_uncov > 0) {
        uint32_t  sg  = 0;
        GramNode *sel = pick_next_gram(ht, queue, &qhead, qtail, &sg);
        if (!sel) break;

        sel->gone = true;

        int picked_rid = -1;
        for (int j = 0; j < sel->count; j++) {
            int rid = sel->rule_ids[j];
            if (!rule_cov[rid]) { picked_rid = rid; break; }
        }
        if (picked_rid < 0) continue;

        rule_cov[picked_rid] = true;
        rule_sel[picked_rid] = (int)sg;
        n_uncov--;

        /* picked_rid no longer contributes to its other grams' degrees. */
        for (int k = 0; k < rule_grams[picked_rid].n; k++) {
            uint32_t other = rule_grams[picked_rid].data[k];
            if (other == sg) continue;
            GramNode *on = gram_ht_find(ht, other);
            if (!on || on->gone) continue;
            on->degree--;
            if (on->degree == 1 && qtail < qcap)
                queue[qtail++] = other;
        }
    }

    /* Step 4: emit GHT entries; warn on rules that could not be covered.
     *
     * Stage assignment (mirrors c_ref/mky_backup/singleton.c):
     *   stage = MIN((pat_len - gram_pos) / 3, MAX_STAGE)
     *   - stage <  2: only bitmap0 + GHT, no next-gram verify
     *   - stage == 2: also verify next gram (at gram_pos+3) against bitmap1.
     *
     * For stage==2 rules we additionally OR the next-gram key into bitmap1
     * so the kernel's bitmap1 lookup confirms the candidate.  Without this
     * bitmap1 stays empty and every stage-2 candidate is filtered out. */
    int stage2_rules = 0;
    ght_count   = 0;
    int dropped = 0;
    memset(bitmap1, 0, sizeof(bitmap1));
    for (int rid = 0; rid < nr; rid++) {
        const Rule *r = &rules[rid];
        if (r->pat_len < 3) continue;
        if (!rule_cov[rid]) {
            dropped++;
            fprintf(stderr,
                    "WARN: rule id=%u uncovered (no available unique gram)\n",
                    r->id);
            continue;
        }

        uint32_t sg   = (uint32_t)rule_sel[rid];
        int      pick = gram_position_in_rule(r, sg);

        // bm0 (singleton bitmap) gets ONE bit per selected rule.  Matches
        // c_ref's bm_arr[0] population in main.c.
        bitmap_set_key(bitmap, sg);

        int      raw_stage = (r->pat_len - pick) / 3;
        int      stage     = raw_stage < MAX_STAGE ? raw_stage : MAX_STAGE;
        bool     stage2    = (stage == 2);
        uint32_t next_key  = 0;
        if (stage2) {
            next_key = make_gram18(r->pattern + pick + 3);
            bitmap_set_key(bitmap1, next_key);
            stage2_rules++;
        }

        ght_entries[ght_count++] = (GhtEntry){
            .gram          = sg,
            .rule_id       = r->id,
            .pre           = -(int8_t)pick,
            .post          = (int8_t)(r->pat_len - pick - 3),
            .len           = r->pat_len,
            .stage2        = stage2,
            .next_gram_key = next_key,
        };
    }
    fprintf(stderr, "singleton: stage2 rules = %d / %d\n",
            stage2_rules, ght_count);

    if (dropped)
        fprintf(stderr, "singleton: %d rule(s) dropped\n", dropped);

    for (int i = 0; i < nr; i++) free(rule_grams[i].data);
    free(rule_grams);
    free(rule_sel);
    free(rule_cov);
    free(queue);
    gram_ht_free(ht);
}

/* -------------------------------------------------------------------------
 * Pattern table: pattern_count × 64B, indexed by ruleId
 * ------------------------------------------------------------------------- */
static uint8_t patterns[MAX_RULES][64];

static void build_patterns(void)
{
    memset(patterns, 0, sizeof(patterns));
    for (int r = 0; r < rule_count; r++) {
        const Rule *rule = &rules[r];
        for (int i = 0; i < rule->pat_len; i++)
            patterns[rule->id][i] = fold_case(rule->pattern[i]);
    }
}

/* -------------------------------------------------------------------------
 * Port / offset tables (mirrors PortOffsetMatcher BRAM layout)
 *
 * PlmEntry (uint32): [0]=valid [1]=isBig [15:2]=offset[13:0] [31:16]=matchKey
 *   port groups:  matchKey = port
 *   ipproto:      matchKey = {0, proto} (low byte)
 *   icmp:         matchKey = {icmpType[7:0], icmpCode[7:0]}
 *
 * Port bitmap:  128 × 64B per table (addr = port[15:9], bit = port[8:0])
 * Port window:  1024 × 4B per table (addr = port[9:0])
 * IP proto:     256 × 4B (addr = proto byte)
 * ICMP:         256 × 4B (addr = icmpType)
 * ------------------------------------------------------------------------- */
static uint8_t portbm[4][PORTLOC_BM_LINES * 64];
static uint32_t portwin[4][PORTLOC_WIN_ENTRIES];
static uint32_t ipproto_win[PORTLOC_SMALL_ENTRIES];
static uint32_t icmp_win[PORTLOC_SMALL_ENTRIES];

static int plm_group_to_tbl(PlmGroup g)
{
    switch (g) {
        case PLM_TCP_DST: return 0;
        case PLM_TCP_SRC: return 1;
        case PLM_UDP_DST: return 2;
        case PLM_UDP_SRC: return 3;
        default:          return -1;
    }
}

static void build_portloc(void)
{
    memset(portbm,      0, sizeof(portbm));
    memset(portwin,     0, sizeof(portwin));
    memset(ipproto_win, 0, sizeof(ipproto_win));
    memset(icmp_win,    0, sizeof(icmp_win));

    for (int r = 0; r < rule_count; r++) {
        const Rule *rule = &rules[r];
        uint32_t plm_entry =
            0x1u |                                        /* valid */
            ((rule->is_big ? 1u : 0u) << 1) |
            (((rule->offset_val & 0x3FFF) << 2));

        int tbl = plm_group_to_tbl(rule->plm_group);
        if (tbl >= 0 && rule->plm_port != 0) {
            uint16_t port = rule->plm_port;
            uint32_t entry = plm_entry | ((uint32_t)port << 16);

            /* bitmap: addr = port[15:9], bit = port[8:0] */
            uint8_t bm_addr = (port >> 9) & 0x7F;
            uint16_t bm_bit = port & 0x1FF;
            portbm[tbl][bm_addr * 64 + bm_bit / 8] |= (1u << (bm_bit % 8));

            /* window: addr = port[9:0] */
            uint16_t win_addr = port & 0x3FF;
            portwin[tbl][win_addr] = entry;
        } else if (rule->plm_group == PLM_IPPROTO) {
            uint32_t entry = plm_entry | ((uint32_t)rule->plm_proto << 16);
            ipproto_win[rule->plm_proto] = entry;
        } else if (rule->plm_group == PLM_ICMP) {
            uint32_t entry = plm_entry |
                ((uint32_t)rule->plm_icmp_type << 16) |
                ((uint32_t)rule->plm_icmp_code << 24);
            icmp_win[rule->plm_icmp_type] = entry;
        }
    }
}

/* -------------------------------------------------------------------------
 * Rule file parser
 * ------------------------------------------------------------------------- */
static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static int url_decode(const char *src, uint8_t *dst, int max_len)
{
    int n = 0;
    while (*src && n < max_len) {
        if (*src == '%' && src[1] && src[2]) {
            int hi = hex_val(src[1]), lo = hex_val(src[2]);
            if (hi >= 0 && lo >= 0) {
                dst[n++] = (uint8_t)(hi << 4 | lo);
                src += 3;
                continue;
            }
        }
        dst[n++] = (uint8_t)*src++;
    }
    return n;
}

static int parse_rules(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;

        Rule rule = {0};
        rule.is_big = false;

        /* parse key=value tokens */
        char id_s[32]={0}, proto_s[64]={0}, off_s[64]={0}, pat_s[512]={0};
        char *tok = strtok(p, " \t\r\n");
        while (tok) {
            char *eq = strchr(tok, '=');
            if (eq) {
                *eq = '\0';
                char *key = tok, *val = eq + 1;
                if (!strcmp(key,"id"))       strncpy(id_s,   val, sizeof(id_s)-1);
                if (!strcmp(key,"protocol")) strncpy(proto_s,val, sizeof(proto_s)-1);
                if (!strcmp(key,"offset"))   strncpy(off_s,  val, sizeof(off_s)-1);
                if (!strcmp(key,"pattern"))  strncpy(pat_s,  val, sizeof(pat_s)-1);
            }
            tok = strtok(NULL, " \t\r\n");
        }
        if (!id_s[0] || !pat_s[0]) continue;

        rule.id = (uint16_t)atoi(id_s);
        rule.pat_len = (uint8_t)url_decode(pat_s, rule.pattern, MAX_PATTERN_LEN);
        if (rule.pat_len < 3 || rule.pat_len > MAX_PATTERN_LEN) continue;

        /* offset */
        if (off_s[0]) {
            char *slash = strchr(off_s, '/');
            rule.offset_val = (uint32_t)atoi(off_s);
            if (slash && !strcasecmp(slash+1, "big")) rule.is_big = true;
        }

        /* protocol/port/direction */
        char *proto_parts[4] = {NULL};
        int nparts = 0;
        char proto_copy[64];
        snprintf(proto_copy, sizeof(proto_copy), "%s", proto_s);
        char *pt = strtok(proto_copy, "/");
        while (pt && nparts < 4) { proto_parts[nparts++] = pt; pt = strtok(NULL, "/"); }

        if (nparts >= 1) {
            const char *p0 = proto_parts[0];
            const char *resolved =
                !strcmp(p0,"6")  ? "tcp" :
                !strcmp(p0,"17") ? "udp" :
                !strcmp(p0,"1")  ? "icmp" :
                !strcmp(p0,"58") ? "icmp" : p0;
            if ((!strcmp(resolved,"tcp") || !strcmp(resolved,"udp")) && nparts >= 3) {
                bool is_tcp = !strcmp(resolved,"tcp");
                bool is_req = !strcmp(proto_parts[2],"request");
                rule.plm_port  = (uint16_t)atoi(proto_parts[1]);
                rule.plm_group = is_tcp ? (is_req ? PLM_TCP_DST : PLM_TCP_SRC)
                                        : (is_req ? PLM_UDP_DST : PLM_UDP_SRC);
            } else if (!strcmp(resolved,"icmp") && nparts >= 3) {
                rule.plm_group     = PLM_ICMP;
                rule.plm_icmp_type = (uint8_t)atoi(proto_parts[1]);
                rule.plm_icmp_code = (uint8_t)atoi(proto_parts[2]);
            } else if (nparts == 1 && isdigit((unsigned char)p0[0])) {
                rule.plm_group = PLM_IPPROTO;
                rule.plm_proto = (uint8_t)atoi(p0);
            }
        }

        if (rule_count < MAX_RULES) rules[rule_count++] = rule;
    }
    fclose(f);
    return rule_count;
}

/* -------------------------------------------------------------------------
 * DB blob assembly
 * ------------------------------------------------------------------------- */
static void write_le32(uint8_t *p, uint32_t v)
{
    p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24;
}

static int write_db(const char *path)
{
    /* Compute offsets — must match DataLoader.bsv: bitmap0, then bitmap1,
     * then GHT (no padding between).  GHT is consumed at base+64+512KB. */
    uint32_t ght_off     = 64 + BITMAP_BYTES + BITMAP_BYTES;
    uint32_t ght_bytes   = (uint32_t)ght_count * GHT_ENTRY_BYTES;
    /* round ruledb_off to 64-byte boundary */
    uint32_t ruledb_off  = (ght_off + ght_bytes + 63) & ~63u;
    uint32_t ruledb_bytes= (uint32_t)rule_count * 64;
    uint32_t portloc_off = (ruledb_off + ruledb_bytes + 63) & ~63u;

    /* portloc size:
       4 × bitmap tables (128 × 64B) + 4 × window tables (1024 × 4B) +
       ipproto (256 × 4B) + icmp (256 × 4B) */
    uint32_t portloc_bytes =
        4 * PORTLOC_BM_LINES * 64 +
        4 * PORTLOC_WIN_ENTRIES * 4 +
        PORTLOC_SMALL_ENTRIES * 4 +
        PORTLOC_SMALL_ENTRIES * 4;

    uint32_t total = portloc_off + portloc_bytes;

    uint8_t *blob = calloc(1, total);
    if (!blob) { fputs("OOM\n", stderr); return -1; }

    /* --- header (64B) --- */
    write_le32(blob + 0,  0xDB600D00u);  /* magic */
    write_le32(blob + 4,  1u);           /* version */
    write_le32(blob + 8,  BITMAP_LINES); /* bitmap_lines */
    write_le32(blob + 12, (uint32_t)ght_count);
    write_le32(blob + 16, (uint32_t)rule_count);
    write_le32(blob + 20, ruledb_off);
    write_le32(blob + 24, portloc_off);

    /* --- bitmap0, bitmap1 --- */
    memcpy(blob + 64,                bitmap,  BITMAP_BYTES);
    memcpy(blob + 64 + BITMAP_BYTES, bitmap1, BITMAP_BYTES);

    /* --- GHT entries --- */
    for (int i = 0; i < ght_count; i++) {
        uint8_t *e = blob + ght_off + i * GHT_ENTRY_BYTES;
        write_le32(e,     ght_entries[i].gram);
        e[4] = ght_entries[i].rule_id & 0xFF;
        e[5] = ght_entries[i].rule_id >> 8;
        e[6] = (uint8_t)ght_entries[i].pre;
        e[7] = (uint8_t)ght_entries[i].post;
        e[8] = ght_entries[i].len;
        /* bit  72       = stage2
         * bits 90:73    = nextGramKey (18 bits)
         * Pack into bytes 9..11 — byte 9 bit 0 holds stage2; the next 18
         * bits start at byte 9 bit 1 and end at byte 11 bit 2. */
        uint32_t nk = ght_entries[i].next_gram_key & 0x3FFFFu;
        e[9]  = (uint8_t)((ght_entries[i].stage2 ? 1u : 0u) | ((nk & 0x7Fu) << 1));
        e[10] = (uint8_t)((nk >> 7) & 0xFFu);
        e[11] = (uint8_t)((nk >> 15) & 0x07u);
        /* [12..15] reserved */
    }

    /* --- patterns --- */
    for (int r = 0; r < rule_count; r++) {
        uint8_t *dst = blob + ruledb_off + (uint32_t)rules[r].id * 64;
        if (ruledb_off + (uint32_t)rules[r].id * 64 + 64 <= total)
            memcpy(dst, patterns[rules[r].id], 64);
    }

    /* --- portloc: bitmaps --- */
    uint32_t off = portloc_off;
    for (int t = 0; t < 4; t++) {
        memcpy(blob + off, portbm[t], PORTLOC_BM_LINES * 64);
        off += PORTLOC_BM_LINES * 64;
    }
    /* --- portloc: windows (1024 × uint32 each) --- */
    for (int t = 0; t < 4; t++) {
        for (int i = 0; i < PORTLOC_WIN_ENTRIES; i++) {
            write_le32(blob + off + i * 4, portwin[t][i]);
        }
        off += PORTLOC_WIN_ENTRIES * 4;
    }
    /* --- portloc: ipproto --- */
    for (int i = 0; i < PORTLOC_SMALL_ENTRIES; i++)
        write_le32(blob + off + i * 4, ipproto_win[i]);
    off += PORTLOC_SMALL_ENTRIES * 4;
    /* --- portloc: icmp --- */
    for (int i = 0; i < PORTLOC_SMALL_ENTRIES; i++)
        write_le32(blob + off + i * 4, icmp_win[i]);

    FILE *fout = fopen(path, "wb");
    if (!fout) { perror(path); free(blob); return -1; }
    fwrite(blob, 1, total, fout);
    fclose(fout);
    free(blob);

    printf("rules=%d  ght_entries=%d  total=%u bytes\n",
           rule_count, ght_count, total);
    printf("  bitmap0  @ 0x%06X  (%u KB)\n", 64, BITMAP_BYTES / 1024);
    printf("  bitmap1  @ 0x%06X  (%u KB)\n", 64 + BITMAP_BYTES, BITMAP_BYTES / 1024);
    printf("  ght      @ 0x%06X  (%u entries × %dB)\n",
           ght_off, ght_count, GHT_ENTRY_BYTES);
    printf("  patterns @ 0x%06X  (%u entries × 64B)\n", ruledb_off, rule_count);
    printf("  portloc  @ 0x%06X  (%u B)\n", portloc_off, portloc_bytes);
    return 0;
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <rule_file> <output_db.bin>\n", argv[0]);
        return 1;
    }
    if (parse_rules(argv[1]) < 0)  return 1;
    if (rule_count == 0) { fputs("no rules parsed\n", stderr); return 1; }
    build_bitmap();
    build_ght();
    build_patterns();
    build_portloc();

    return write_db(argv[2]);
}
