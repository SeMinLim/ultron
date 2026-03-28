// ref: https://www.geeksforgeeks.org/dsa/cuckoo-hashing/

#ifndef CUCKOO_HASH_H
#define CUCKOO_HASH_H

#include <stdint.h>
#include <stdbool.h>

#define CUCKOO_EMPTY    INT32_MIN
#define CUCKOO_MAX_LOOP 8

typedef struct {
    int *table[2];
    int  capacity;
    int  count;
} CuckooHash;

CuckooHash *cuckoo_create(int capacity);
void        cuckoo_destroy(CuckooHash *ht);

bool cuckoo_insert(CuckooHash *ht, int key);
bool cuckoo_lookup(const CuckooHash *ht, int key);
bool cuckoo_delete(CuckooHash *ht, int key);

void cuckoo_print(const CuckooHash *ht);

#endif
