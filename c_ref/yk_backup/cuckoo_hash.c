// ref: https://www.geeksforgeeks.org/dsa/cuckoo-hashing/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cuckoo_hash.h"

static int h1(int key, int cap) { return abs(key % cap); }
static int h2(int key, int cap) { return abs((key / cap) % cap); }

static int hash_fn(int table_id, int key, int cap)
{
    return table_id == 0 ? h1(key, cap) : h2(key, cap);
}

CuckooHash *cuckoo_create(int capacity)
{
    CuckooHash *ht = malloc(sizeof(CuckooHash));
    ht->capacity = capacity;
    ht->count    = 0;
    for (int i = 0; i < 2; i++) {
        ht->table[i] = malloc(capacity * sizeof(int));
        for (int j = 0; j < capacity; j++)
            ht->table[i][j] = CUCKOO_EMPTY;
    }
    return ht;
}

void cuckoo_destroy(CuckooHash *ht)
{
    for (int i = 0; i < 2; i++)
        free(ht->table[i]);
    free(ht);
}

bool cuckoo_lookup(const CuckooHash *ht, int key)
{
    int p1 = h1(key, ht->capacity);
    int p2 = h2(key, ht->capacity);
    return ht->table[0][p1] == key || ht->table[1][p2] == key;
}

bool cuckoo_delete(CuckooHash *ht, int key)
{
    int p1 = h1(key, ht->capacity);
    if (ht->table[0][p1] == key) {
        ht->table[0][p1] = CUCKOO_EMPTY;
        ht->count--;
        return true;
    }
    int p2 = h2(key, ht->capacity);
    if (ht->table[1][p2] == key) {
        ht->table[1][p2] = CUCKOO_EMPTY;
        ht->count--;
        return true;
    }
    return false;
}

bool cuckoo_insert(CuckooHash *ht, int key)
{
    if (cuckoo_lookup(ht, key))
        return true;

    int cur = key;
    int tid = 0;

    for (int loop = 0; loop < CUCKOO_MAX_LOOP; loop++) {
        int pos = hash_fn(tid, cur, ht->capacity);
        if (ht->table[tid][pos] == CUCKOO_EMPTY) {
            ht->table[tid][pos] = cur;
            ht->count++;
            return true;
        }
        int evicted = ht->table[tid][pos];
        ht->table[tid][pos] = cur;
        cur = evicted;
        tid ^= 1;
    }

    fprintf(stderr, "cuckoo_insert: cycle detected, rehash needed (key=%d)\n", cur);
    return false;
}

void cuckoo_print(const CuckooHash *ht)
{
    for (int i = 0; i < 2; i++) {
        printf("table[%d]: ", i);
        for (int j = 0; j < ht->capacity; j++) {
            if (ht->table[i][j] == CUCKOO_EMPTY)
                printf("  -");
            else
                printf("%3d", ht->table[i][j]);
        }
        printf("\n");
    }
}
