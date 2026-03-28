#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rule_loader.h"

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int url_decode(const char *src, char *dst, int dst_max)
{
    int len = 0;
    while (*src && len < dst_max - 1) {
        if (*src == '%' && hex_val(src[1]) >= 0 && hex_val(src[2]) >= 0) {
            dst[len++] = (char)((hex_val(src[1]) << 4) | hex_val(src[2]));
            src += 3;
        } else {
            dst[len++] = *src++;
        }
    }
    dst[len] = '\0';
    return len;
}

RuleSet *rules_load(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;

    RuleSet *rs = malloc(sizeof(RuleSet));
    rs->rules   = malloc(MAX_RULES * sizeof(Rule));
    rs->count   = 0;

    char line[2048];
    while (fgets(line, sizeof(line), fp) && rs->count < MAX_RULES) {
        char *p = strstr(line, "id=");
        if (!p) continue;
        int id = atoi(p + 3);

        char *pat = strstr(line, "pattern=");
        if (!pat) continue;
        pat += 8;

        int end = (int)strcspn(pat, " \t\r\n");
        pat[end] = '\0';

        Rule *r = &rs->rules[rs->count];
        r->id      = id;
        r->pat_len = url_decode(pat, r->pattern, MAX_PATTERN_LEN);
        rs->count++;
    }

    fclose(fp);
    return rs;
}

void rules_free(RuleSet *rs)
{
    if (!rs) return;
    free(rs->rules);
    free(rs);
}
