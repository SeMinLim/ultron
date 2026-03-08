#include "id_array.h"

int id_array_append_unique(uint32_t *ids, size_t *count, size_t max_count, uint32_t id)
{
    if (!ids || !count) {
        return 0;
    }

    for (size_t i = 0; i < *count; i++) {
        if (ids[i] == id) {
            return 1;
        }
    }

    if (*count >= max_count) {
        return 0;
    }

    ids[(*count)++] = id;
    return 1;
}
