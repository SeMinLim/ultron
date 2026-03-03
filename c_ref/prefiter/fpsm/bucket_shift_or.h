#ifndef BUCKET_SHIFT_OR_H
#define BUCKET_SHIFT_OR_H

#include <stddef.h>
#include <stdint.h>

#define SHIFT_OR_ALPHABET_SIZE 256
#define SHIFT_OR_MAX_PATTERN_LEN 64
#define SHIFT_OR_PARALLEL 8
#define SHIFT_OR_MIN_LEN 16

#define SHIFT_OR_BUCKET_WIDTH 16

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64a;

#ifdef __GNUC__
#define really_inline __attribute__((always_inline)) inline
#else
#define really_inline inline
#endif

typedef struct {
    u64a mask[SHIFT_OR_ALPHABET_SIZE];
    u64a pre_shifted[SHIFT_OR_PARALLEL + 1][SHIFT_OR_ALPHABET_SIZE];
    u32 pattern_len;
} shift_or_t;

typedef struct {
    u64a mask[SHIFT_OR_ALPHABET_SIZE];
    u64a pre_shifted[SHIFT_OR_PARALLEL + 1][SHIFT_OR_ALPHABET_SIZE];
    u32 pattern_len;
    u32 pattern_count;
} shift_or_bucket_t;

void shiftOrInit(shift_or_t *so, const u8 *pattern, size_t len);

const u8 *shiftOrExec(const shift_or_t *so, const u8 *buf, const u8 *buf_end);

void shiftOrBucketInit(shift_or_bucket_t *b, const u8 *pattern, size_t len);

int shiftOrBucketAddPattern(shift_or_bucket_t *b, const u8 *pattern, size_t len);

const u8 *shiftOrExecBucket(const shift_or_bucket_t *b, const u8 *buf,
                            const u8 *buf_end);

#endif
