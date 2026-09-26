// ref: https://www.geeksforgeeks.org/dsa/hash-table-data-structure/

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "hashtable.h"

static int h1(int key, int cap) { return (int)((unsigned)key % (unsigned)cap); }
static int h2(int key, int cap) { return (int)(((unsigned)key * 2654435761u) % (unsigned)cap); }

static int slot(int tid, int key, int cap)
{
    return tid == 0 ? h1(key, cap) : h2(key, cap);
}

static size_t allocation_usable_bytes(const void *ptr)
{
    return ptr ? malloc_usable_size((void *)ptr) : 0;
}

HashTable *ht_create(int capacity)
{
    HashTable *ht = malloc(sizeof(HashTable));
    ht->capacity  = capacity;
    ht->count     = 0;
    for (int i = 0; i < 2; i++) {
        ht->table[i] = malloc(capacity * sizeof(HEntry));
        for (int j = 0; j < capacity; j++)
            ht->table[i][j].key = CUCKOO_EMPTY;
    }
    return ht;
}

void ht_destroy(HashTable *ht)
{
    for (int i = 0; i < 2; i++)
        free(ht->table[i]);
    free(ht);
}

bool ht_lookup(const HashTable *ht, int key, int *val_out)
{
    if (key == CUCKOO_EMPTY) return false;  
    int p0 = h1(key, ht->capacity);
    if (ht->table[0][p0].key == key) {
        if (val_out) *val_out = ht->table[0][p0].val;
        return true;
    }
    int p1 = h2(key, ht->capacity);
    if (ht->table[1][p1].key == key) {
        if (val_out) *val_out = ht->table[1][p1].val;
        return true;
    }
    return false;
}

bool ht_delete(HashTable *ht, int key)
{
    if (key == CUCKOO_EMPTY) return false;   
    int p0 = h1(key, ht->capacity);
    if (ht->table[0][p0].key == key) {
        ht->table[0][p0].key = CUCKOO_EMPTY;
        ht->count--;
        return true;
    }
    int p1 = h2(key, ht->capacity);
    if (ht->table[1][p1].key == key) {
        ht->table[1][p1].key = CUCKOO_EMPTY;
        ht->count--;
        return true;
    }
    return false;
}

size_t ht_memory_usage_bytes(const HashTable *ht)
{
    if (!ht) return 0;
    return sizeof(*ht) + 2U * (size_t)ht->capacity * sizeof(HEntry);
}

size_t ht_runtime_memory_usage_bytes(const HashTable *ht)
{
    if (!ht) return 0;
    return allocation_usable_bytes(ht)
         + allocation_usable_bytes(ht->table[0])
         + allocation_usable_bytes(ht->table[1]);
}

int ht_total_slots(const HashTable *ht)
{
    if (!ht) return 0;
    return ht->capacity * 2;
}

size_t ht_occupied_entry_bytes(const HashTable *ht)
{
    if (!ht) return 0;
    return (size_t)ht->count * sizeof(HEntry);
}

bool ht_insert(HashTable *ht, int key, int val)
{
    if (key == CUCKOO_EMPTY) return false;   
    int existing_val;
    if (ht_lookup(ht, key, &existing_val)) {
        int p0 = h1(key, ht->capacity);
        if (ht->table[0][p0].key == key) ht->table[0][p0].val = val;
        else                              ht->table[1][h2(key, ht->capacity)].val = val;
        return true;
    }

    HEntry cur = { key, val };
    int tid = 0;

    for (int loop = 0; loop < HT_MAX_LOOP; loop++) {
        int pos = slot(tid, cur.key, ht->capacity);
        if (ht->table[tid][pos].key == CUCKOO_EMPTY) {
            ht->table[tid][pos] = cur;
            ht->count++;
            return true;
        }
        HEntry evicted = ht->table[tid][pos];
        ht->table[tid][pos] = cur;
        cur = evicted;
        tid ^= 1;
    }

    fprintf(stderr, "ht_insert: cycle detected, rehash needed (key=%d)\n", cur.key);
    return false;
}

void ht_print(const HashTable *ht)
{
    for (int i = 0; i < 2; i++) {
        printf("table[%d]: ", i);
        for (int j = 0; j < ht->capacity; j++) {
            if (ht->table[i][j].key == CUCKOO_EMPTY)
                printf("  [  -]");
            else
                printf("  [%d:%d]", ht->table[i][j].key, ht->table[i][j].val);
        }
        printf("\n");
    }
}
