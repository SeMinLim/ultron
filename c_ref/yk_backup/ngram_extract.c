#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ngram_extract.h"

NGramSet *ngram_extract(const uint8_t *buf, int len, int n)
{
    if (!buf || len < n || n <= 0) return NULL;

    int count = len - n + 1;

    NGramSet *ns = malloc(sizeof(NGramSet));
    ns->n     = n;
    ns->count = count;
    ns->data  = malloc(count * n);

    for (int i = 0; i < count; i++)
        memcpy(ns->data + i * n, buf + i, n);

    return ns;
}

void ngram_free(NGramSet *ns)
{
    if (!ns) return;
    free(ns->data);
    free(ns);
}

void ngram_print(const NGramSet *ns)
{
    if (!ns) return;
    for (int i = 0; i < ns->count; i++) {
        printf("[%d] ", i);
        for (int j = 0; j < ns->n; j++) {
            uint8_t b = ns->data[i * ns->n + j];
            if (b >= 0x20 && b < 0x7f)
                printf("%c", b);
            else
                printf("\\x%02x", b);
        }
        printf("\n");
    }
}
