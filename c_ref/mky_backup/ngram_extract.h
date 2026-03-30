#ifndef NGRAM_EXTRACT_H
#define NGRAM_EXTRACT_H

#include <stdint.h>

typedef struct {
    uint8_t *data;
    int      n;
    int      count;
} NGramSet;

NGramSet *ngram_extract(const uint8_t *buf, int len, int n);
void      ngram_free(NGramSet *ns);
void      ngram_print(const NGramSet *ns);

#endif
