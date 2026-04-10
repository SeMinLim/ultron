#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <stdint.h>

#define MAX_PATTERN_LEN 256
#define MAX_RULES       4096

typedef struct {
    int      id;
    char     pattern[MAX_PATTERN_LEN];
    int      pat_len;
    uint8_t  proto;
    uint16_t port;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    int      is_request;
    int      offset_val;
    int      offset_mode;
    int      priority;
} Rule;

typedef struct {
    Rule *rules;
    int   count;
} RuleSet;

RuleSet *rules_load(const char *filename);
void     rules_free(RuleSet *rs);

#endif
