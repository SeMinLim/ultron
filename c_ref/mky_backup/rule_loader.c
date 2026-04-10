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

        char     proto_str[32] = {0};
        char     field2[32]    = {0};
        char     dir_str[16]   = {0};
        uint16_t port          = 0;
        uint8_t  icmp_type     = 0;
        uint8_t  icmp_code     = 0;
        int      is_request    = -1;

        char *pr = strstr(line, "protocol=");
        if (pr) {
            pr += 9;
            char tmp[64] = {0};
            int tlen = (int)strcspn(pr, " \t\r\n");
            if (tlen > 63) tlen = 63;
            memcpy(tmp, pr, (size_t)tlen);
            sscanf(tmp, "%31[^/]/%31[^/]/%15s", proto_str, field2, dir_str);

            if (strchr(field2, ',')) {
                unsigned int t = 0, c = 0;
                sscanf(field2, "%u,%u", &t, &c);
                icmp_type = (uint8_t)t;
                icmp_code = (uint8_t)c;
            } else {
                port = (uint16_t)atoi(field2);
                if      (strcmp(dir_str, "request")  == 0) is_request = 1;
                else if (strcmp(dir_str, "response") == 0) is_request = 0;
            }
        }

        uint8_t proto = 0;
        if      (strcmp(proto_str, "tcp")  == 0) proto = 6;
        else if (strcmp(proto_str, "udp")  == 0) proto = 17;
        else if (strcmp(proto_str, "icmp") == 0) proto = 1;
        else                                      proto = (uint8_t)atoi(proto_str);

        int offset_val  = 0;
        int offset_mode = 0;
        char *of = strstr(line, "offset=");
        if (of) {
            of += 7;
            char sz[16] = {0};
            sscanf(of, "%d/%15s", &offset_val, sz);
            if      (strcmp(sz, "small") == 0) offset_mode = 1;
            else if (strcmp(sz, "big")   == 0) offset_mode = 2;
            else if (strcmp(sz, "same")  == 0) offset_mode = 3;
        }

        int priority = 0;
        char *prio = strstr(line, "priority=");
        if (prio) {
            prio += 9;
            if      (strncmp(prio, "high", 4) == 0) priority = 2;
            else if (strncmp(prio, "low",  3) == 0) priority = 1;
        }

        char decoded[MAX_PATTERN_LEN];
        int  decoded_len = url_decode(pat, decoded, MAX_PATTERN_LEN);
        if (decoded_len > 64)
            continue;

        Rule *r        = &rs->rules[rs->count];
        r->id          = id;
        r->pat_len     = decoded_len;
        memcpy(r->pattern, decoded, (size_t)decoded_len + 1);
        r->proto       = proto;
        r->port        = port;
        r->icmp_type   = icmp_type;
        r->icmp_code   = icmp_code;
        r->is_request  = is_request;
        r->offset_val  = offset_val;
        r->offset_mode = offset_mode;
        r->priority    = priority;
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
