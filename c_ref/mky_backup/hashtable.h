// ref: https://www.geeksforgeeks.org/dsa/hash-table-data-structure/

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdbool.h>
#include "cuckoo_hash.h"

#define HT_MAX_LOOP 64

typedef struct {
    int key;
    int val;
} HEntry;

typedef struct {
    HEntry *table[2];
    int     capacity;
    int     count;
} HashTable;

HashTable *ht_create(int capacity);
void       ht_destroy(HashTable *ht);

bool ht_insert(HashTable *ht, int key, int val);
bool ht_lookup(const HashTable *ht, int key, int *val_out);
bool ht_delete(HashTable *ht, int key);

void ht_print(const HashTable *ht);

#endif
