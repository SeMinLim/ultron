#ifndef CUCKOO_HASH_H
#define CUCKOO_HASH_H

#include <stddef.h>
#include <stdint.h>

#define CUCKOO_MAX_KICK 64
#define CUCKOO_EMPTY_KEY UINT64_MAX

typedef struct {
    uint64_t *keys1;
    uint64_t *keys2;
    uint64_t *vals1;
    uint64_t *vals2;
    size_t capacity;
    size_t count;
} cuckoo_hash_t;

int cuckoo_hash_init(cuckoo_hash_t *ch, size_t capacity);
void cuckoo_hash_free(cuckoo_hash_t *ch);
int cuckoo_hash_insert(cuckoo_hash_t *ch, uint64_t key, uint64_t value);
int cuckoo_hash_lookup(const cuckoo_hash_t *ch, uint64_t key, uint64_t *out_value);
int cuckoo_hash_remove(cuckoo_hash_t *ch, uint64_t key);

#endif
