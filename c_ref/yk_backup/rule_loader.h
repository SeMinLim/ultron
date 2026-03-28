#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#define MAX_PATTERN_LEN 256
#define MAX_RULES       4096

typedef struct {
    int  id;
    char pattern[MAX_PATTERN_LEN];
    int  pat_len;
} Rule;

typedef struct {
    Rule *rules;
    int   count;
} RuleSet;

RuleSet *rules_load(const char *filename);
void     rules_free(RuleSet *rs);

#endif
