#ifndef PREFILTER_ID_ARRAY_H
#define PREFILTER_ID_ARRAY_H

#include <stddef.h>
#include <stdint.h>

int id_array_append_unique(uint32_t *ids, size_t *count, size_t max_count, uint32_t id);

#endif
