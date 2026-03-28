#include "cuckoo_hash.h"
#include <stdlib.h>

static size_t primary_index(uint64_t key, size_t capacity)
{
    return key % capacity;
}

static size_t secondary_index(uint64_t key, size_t capacity)
{
    return (key / (capacity + 1)) % capacity;
}

int cuckoo_hash_init(cuckoo_hash_t *ch, size_t capacity)
{
    if (!ch || capacity == 0) {
        return -1;
    }

    (*ch).keys1 = calloc(capacity, sizeof(uint64_t));
    (*ch).keys2 = calloc(capacity, sizeof(uint64_t));
    (*ch).vals1 = calloc(capacity, sizeof(uint64_t));
    (*ch).vals2 = calloc(capacity, sizeof(uint64_t));
    if (!(*ch).keys1 || !(*ch).keys2 || !(*ch).vals1 || !(*ch).vals2) {
        free((*ch).keys1);
        free((*ch).keys2);
        free((*ch).vals1);
        free((*ch).vals2);
        return -1;
    }
    for (size_t i = 0; i < capacity; i++) {
        (*ch).keys1[i] = CUCKOO_EMPTY_KEY;
        (*ch).keys2[i] = CUCKOO_EMPTY_KEY;
    }
    (*ch).capacity = capacity;
    (*ch).count = 0;
    return 0;
}

void cuckoo_hash_free(cuckoo_hash_t *ch)
{
    if (!ch) {
        return;
    }

    free((*ch).keys1);
    free((*ch).keys2);
    free((*ch).vals1);
    free((*ch).vals2);
    (*ch).keys1 = NULL;
    (*ch).keys2 = NULL;
    (*ch).vals1 = NULL;
    (*ch).vals2 = NULL;
    (*ch).capacity = 0;
    (*ch).count = 0;
}

#define INSERT_OK_NEW 1
#define INSERT_OK_UPD 2
#define INSERT_NEED_KICK 0

static int place_or_kick(cuckoo_hash_t *ch,
                         uint64_t key,
                         uint64_t value,
                         uint64_t *out_kicked_key,
                         uint64_t *out_kicked_val)
{
    size_t capacity = (*ch).capacity;
    size_t slot1 = primary_index(key, capacity);
    size_t slot2 = secondary_index(key, capacity);

    if ((*ch).keys1[slot1] == CUCKOO_EMPTY_KEY) {
        (*ch).keys1[slot1] = key;
        (*ch).vals1[slot1] = value;
        return INSERT_OK_NEW;
    }

    if ((*ch).keys1[slot1] == key) {
        (*ch).vals1[slot1] = value;
        return INSERT_OK_UPD;
    }

    if ((*ch).keys2[slot2] == CUCKOO_EMPTY_KEY) {
        (*ch).keys2[slot2] = key;
        (*ch).vals2[slot2] = value;
        return INSERT_OK_NEW;
    }

    if ((*ch).keys2[slot2] == key) {
        (*ch).vals2[slot2] = value;
        return INSERT_OK_UPD;
    }

    *out_kicked_key = (*ch).keys1[slot1];
    *out_kicked_val = (*ch).vals1[slot1];
    (*ch).keys1[slot1] = key;
    (*ch).vals1[slot1] = value;
    return INSERT_NEED_KICK;
}

int cuckoo_hash_insert(cuckoo_hash_t *ch, uint64_t key, uint64_t value)
{
    if (!ch || (*ch).capacity == 0) {
        return -1;
    }

    uint64_t kicked_key;
    uint64_t kicked_val;
    int r = place_or_kick(ch, key, value, &kicked_key, &kicked_val);

    if (r == INSERT_OK_NEW) {
        (*ch).count++;
        return 0;
    }
    if (r == INSERT_OK_UPD) {
        return 0;
    }

    uint64_t cur_key = kicked_key;
    uint64_t cur_val = kicked_val;
    int in_table2 = 0;

    for (int kick = 0; kick < CUCKOO_MAX_KICK; kick++) {
        size_t capacity = (*ch).capacity;
        if (!in_table2) {
            size_t slot2 = secondary_index(cur_key, capacity);
            if ((*ch).keys2[slot2] == CUCKOO_EMPTY_KEY) {
                (*ch).keys2[slot2] = cur_key;
                (*ch).vals2[slot2] = cur_val;
                (*ch).count++;
                return 0;
            }

            if ((*ch).keys2[slot2] == cur_key) {
                (*ch).vals2[slot2] = cur_val;
                return 0;
            }

            uint64_t next_key = (*ch).keys2[slot2];
            uint64_t next_val = (*ch).vals2[slot2];
            (*ch).keys2[slot2] = cur_key;
            (*ch).vals2[slot2] = cur_val;
            cur_key = next_key;
            cur_val = next_val;
            in_table2 = 1;
        } else {
            size_t slot1 = primary_index(cur_key, capacity);
            if ((*ch).keys1[slot1] == CUCKOO_EMPTY_KEY) {
                (*ch).keys1[slot1] = cur_key;
                (*ch).vals1[slot1] = cur_val;
                (*ch).count++;
                return 0;
            }

            if ((*ch).keys1[slot1] == cur_key) {
                (*ch).vals1[slot1] = cur_val;
                return 0;
            }

            uint64_t next_key = (*ch).keys1[slot1];
            uint64_t next_val = (*ch).vals1[slot1];
            (*ch).keys1[slot1] = cur_key;
            (*ch).vals1[slot1] = cur_val;
            cur_key = next_key;
            cur_val = next_val;
            in_table2 = 0;
        }
    }
    return -1;
}

int cuckoo_hash_lookup(const cuckoo_hash_t *ch, uint64_t key, uint64_t *out_value)
{
    if (!ch || (*ch).capacity == 0) {
        return 0;
    }

    size_t slot1 = primary_index(key, (*ch).capacity);
    size_t slot2 = secondary_index(key, (*ch).capacity);

    if ((*ch).keys1[slot1] == key) {
        if (out_value) {
            *out_value = (*ch).vals1[slot1];
        }
        return 1;
    }

    if ((*ch).keys2[slot2] == key) {
        if (out_value) {
            *out_value = (*ch).vals2[slot2];
        }
        return 1;
    }

    return 0;
}

int cuckoo_hash_remove(cuckoo_hash_t *ch, uint64_t key)
{
    if (!ch || (*ch).capacity == 0) {
        return 0;
    }

    size_t slot1 = primary_index(key, (*ch).capacity);
    size_t slot2 = secondary_index(key, (*ch).capacity);

    if ((*ch).keys1[slot1] == key) {
        (*ch).keys1[slot1] = CUCKOO_EMPTY_KEY;
        (*ch).count--;
        return 1;
    }

    if ((*ch).keys2[slot2] == key) {
        (*ch).keys2[slot2] = CUCKOO_EMPTY_KEY;
        (*ch).count--;
        return 1;
    }

    return 0;
}
