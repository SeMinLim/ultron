#include "bucket_shift_or.h"
#include <string.h>

static void build_pre_shifted(u64a pre_shifted[SHIFT_OR_PARALLEL + 1][SHIFT_OR_ALPHABET_SIZE],
                              const u64a mask[SHIFT_OR_ALPHABET_SIZE])
{
    for (u32 shift = 1; shift <= SHIFT_OR_PARALLEL; shift++) {
        for (int c = 0; c < SHIFT_OR_ALPHABET_SIZE; c++) {
            pre_shifted[shift][c] = mask[c] << shift;
        }
    }
}

static void reset_mask(u64a mask[SHIFT_OR_ALPHABET_SIZE])
{
    memset(mask, 0xFF, SHIFT_OR_ALPHABET_SIZE * sizeof(u64a));
}

static void apply_pattern_to_mask(u64a mask[SHIFT_OR_ALPHABET_SIZE],
                                  const u8 *pattern,
                                  size_t len)
{
    for (size_t i = 0; i < len; i++) {
        mask[pattern[i]] &= ~(1ULL << i);
    }
}

static void reset_bucket_masks(shift_or_bucket_t *b)
{
    for (u8 bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
        reset_mask((*b).mask[bucket]);
    }
}

static u8 pick_bucket(const shift_or_bucket_t *b)
{
    u8 best = 0;
    u16 best_load = 0xFFFF;

    for (u8 bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
        u8 bit = (u8)(1U << bucket);
        if (((*b).active_buckets & bit) == 0) {
            return bucket;
        }
        if ((*b).bucket_load[bucket] < best_load) {
            best = bucket;
            best_load = (*b).bucket_load[bucket];
        }
    }

    return best;
}

void shiftOrInit(shift_or_t *so, const u8 *pattern, size_t len)
{
    if (len == 0 || len > SHIFT_OR_MAX_PATTERN_LEN) {
        (*so).pattern_len = 0;
        return;
    }

    (*so).pattern_len = (u32)len;
    reset_mask((*so).mask);
    apply_pattern_to_mask((*so).mask, pattern, len);
    build_pre_shifted((*so).pre_shifted, (*so).mask);
}

void shiftOrBucketInit(shift_or_bucket_t *b, const u8 *pattern, size_t len)
{
    if (len == 0 || len > SHIFT_OR_MAX_PATTERN_LEN) {
        memset(b, 0, sizeof(*b));
        return;
    }

    memset(b, 0, sizeof(*b));
    (*b).pattern_len = (u32)len;
    (*b).pattern_count = 1;
    (*b).active_buckets = 0x1;
    (*b).bucket_load[0] = 1;

    reset_bucket_masks(b);
    apply_pattern_to_mask((*b).mask[0], pattern, len);
}

int shiftOrBucketAddPatternWithBucket(shift_or_bucket_t *b,
                                      const u8 *pattern,
                                      size_t len,
                                      u8 *out_bucket)
{
    if ((*b).pattern_len == 0 || len != (*b).pattern_len) {
        return -1;
    }

    u8 bucket = pick_bucket(b);
    apply_pattern_to_mask((*b).mask[bucket], pattern, len);
    (*b).active_buckets |= (u8)(1U << bucket);
    (*b).bucket_load[bucket]++;
    (*b).pattern_count++;

    if (out_bucket) {
        *out_bucket = bucket;
    }

    return 0;
}

int shiftOrBucketAddPattern(shift_or_bucket_t *b, const u8 *pattern, size_t len)
{
    return shiftOrBucketAddPatternWithBucket(b, pattern, len, NULL);
}

static really_inline const u8 *shiftOrFwdSlow(const shift_or_t *so,
                                              const u8 *buf,
                                              const u8 *buf_end,
                                              u64a state)
{
    u32 pattern_len = (*so).pattern_len;
    if (pattern_len == 0 || (size_t)(buf_end - buf) < pattern_len) {
        return buf_end;
    }

    const u64a match_bit = 1ULL << pattern_len;

    for (const u8 *cur = buf; cur < buf_end; cur++) {
        state |= (*so).mask[*cur];
        state <<= 1;
        if ((state & match_bit) == 0) {
            return cur - pattern_len + 1;
        }
    }

    return buf_end;
}

static really_inline const u8 *shiftOrFwd64(const shift_or_t *so,
                                            const u8 *buf,
                                            const u8 *buf_end)
{
    if ((size_t)(buf_end - buf) < 64) {
        return buf_end;
    }

    const u64a match_bit = 1ULL << 63;
    u64a state = ~0ULL;

    for (const u8 *cur = buf; cur < buf_end; cur++) {
        state = (state << 1) | (*so).mask[*cur];
        if ((state & match_bit) == 0) {
            return cur - 63;
        }
    }

    return buf_end;
}

static really_inline const u8 *shiftOrFwdBlock(const shift_or_t *so,
                                                const u8 *buf,
                                                u64a state,
                                                const u64a match_bit,
                                                u64a *out_state)
{
    u32 pattern_len = (*so).pattern_len;
    u64a c0 = (*so).pre_shifted[1][buf[0]];
    u64a c1 = (*so).pre_shifted[2][buf[0]] | (*so).pre_shifted[1][buf[1]];
    u64a c2 = (*so).pre_shifted[3][buf[0]] | (*so).pre_shifted[2][buf[1]] |
              (*so).pre_shifted[1][buf[2]];
    u64a c3 = (*so).pre_shifted[4][buf[0]] | (*so).pre_shifted[3][buf[1]] |
              (*so).pre_shifted[2][buf[2]] | (*so).pre_shifted[1][buf[3]];
    u64a c4 = (*so).pre_shifted[5][buf[0]] | (*so).pre_shifted[4][buf[1]] |
              (*so).pre_shifted[3][buf[2]] | (*so).pre_shifted[2][buf[3]] |
              (*so).pre_shifted[1][buf[4]];
    u64a c5 = (*so).pre_shifted[6][buf[0]] | (*so).pre_shifted[5][buf[1]] |
              (*so).pre_shifted[4][buf[2]] | (*so).pre_shifted[3][buf[3]] |
              (*so).pre_shifted[2][buf[4]] | (*so).pre_shifted[1][buf[5]];
    u64a c6 = (*so).pre_shifted[7][buf[0]] | (*so).pre_shifted[6][buf[1]] |
              (*so).pre_shifted[5][buf[2]] | (*so).pre_shifted[4][buf[3]] |
              (*so).pre_shifted[3][buf[4]] | (*so).pre_shifted[2][buf[5]] |
              (*so).pre_shifted[1][buf[6]];
    u64a c7 = (*so).pre_shifted[8][buf[0]] | (*so).pre_shifted[7][buf[1]] |
              (*so).pre_shifted[6][buf[2]] | (*so).pre_shifted[5][buf[3]] |
              (*so).pre_shifted[4][buf[4]] | (*so).pre_shifted[3][buf[5]] |
              (*so).pre_shifted[2][buf[6]] | (*so).pre_shifted[1][buf[7]];

    u64a s1 = (state << 1) | c0;
    if ((s1 & match_bit) == 0) {
        return buf - pattern_len + 1;
    }

    u64a s2 = (state << 2) | c1;
    if ((s2 & match_bit) == 0) {
        return buf - pattern_len + 2;
    }

    u64a s3 = (state << 3) | c2;
    if ((s3 & match_bit) == 0) {
        return buf - pattern_len + 3;
    }

    u64a s4 = (state << 4) | c3;
    if ((s4 & match_bit) == 0) {
        return buf - pattern_len + 4;
    }

    u64a s5 = (state << 5) | c4;
    if ((s5 & match_bit) == 0) {
        return buf - pattern_len + 5;
    }

    u64a s6 = (state << 6) | c5;
    if ((s6 & match_bit) == 0) {
        return buf - pattern_len + 6;
    }

    u64a s7 = (state << 7) | c6;
    if ((s7 & match_bit) == 0) {
        return buf - pattern_len + 7;
    }

    u64a s8 = (state << 8) | c7;
    if ((s8 & match_bit) == 0) {
        return buf - pattern_len + 8;
    }

    *out_state = s8;
    return NULL;
}

const u8 *shiftOrExec(const shift_or_t *so, const u8 *buf, const u8 *buf_end)
{
    if (!buf || !buf_end || buf >= buf_end) {
        return buf_end;
    }

    u32 pattern_len = (*so).pattern_len;
    if (pattern_len == 0) {
        return buf_end;
    }

    if (pattern_len == 64) {
        return shiftOrFwd64(so, buf, buf_end);
    }

    size_t len = (size_t)(buf_end - buf);
    if (len < pattern_len) {
        return buf_end;
    }

    if (len < SHIFT_OR_MIN_LEN) {
        return shiftOrFwdSlow(so, buf, buf_end, ~1ULL);
    }

    const u64a match_bit = 1ULL << pattern_len;
    u64a state = ~1ULL;
    const u8 *cursor = buf;

    while (cursor + SHIFT_OR_PARALLEL <= buf_end) {
        const u8 *match = shiftOrFwdBlock(so, cursor, state, match_bit, &state);
        if (match) {
            return match;
        }
        cursor += SHIFT_OR_PARALLEL;
    }

    return shiftOrFwdSlow(so, cursor, buf_end, state);
}

const u8 *shiftOrExecBucketWithBitmap(const shift_or_bucket_t *b,
                                      const u8 *buf,
                                      const u8 *buf_end,
                                      u8 *out_bucket_bitmap)
{
    if (out_bucket_bitmap) {
        *out_bucket_bitmap = 0;
    }

    if (!b || !buf || !buf_end || buf >= buf_end) {
        return buf_end;
    }

    u32 pattern_len = (*b).pattern_len;
    if (pattern_len == 0 || (*b).active_buckets == 0) {
        return buf_end;
    }

    size_t span = (size_t)(buf_end - buf);
    if (span < pattern_len) {
        return buf_end;
    }

    u64a state[SHIFT_OR_BUCKETS];
    for (u8 bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
        state[bucket] = (pattern_len == 64) ? ~0ULL : ~1ULL;
    }

    u8 active = (*b).active_buckets;

    if (pattern_len == 64) {
        const u64a match_bit = 1ULL << 63;
        for (const u8 *cur = buf; cur < buf_end; cur++) {
            u8 bitmap = 0;
            for (u8 bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
                u8 bit = (u8)(1U << bucket);
                if ((active & bit) == 0) {
                    continue;
                }
                state[bucket] = (state[bucket] << 1) | (*b).mask[bucket][*cur];
                if ((state[bucket] & match_bit) == 0) {
                    bitmap |= bit;
                }
            }
            if (bitmap != 0) {
                if (out_bucket_bitmap) {
                    *out_bucket_bitmap = bitmap;
                }
                return cur - 63;
            }
        }
        return buf_end;
    }

    const u64a match_bit = 1ULL << pattern_len;
    for (const u8 *cur = buf; cur < buf_end; cur++) {
        u8 bitmap = 0;
        for (u8 bucket = 0; bucket < SHIFT_OR_BUCKETS; bucket++) {
            u8 bit = (u8)(1U << bucket);
            if ((active & bit) == 0) {
                continue;
            }
            state[bucket] |= (*b).mask[bucket][*cur];
            state[bucket] <<= 1;
            if ((state[bucket] & match_bit) == 0) {
                bitmap |= bit;
            }
        }
        if (bitmap != 0) {
            if (out_bucket_bitmap) {
                *out_bucket_bitmap = bitmap;
            }
            return cur - pattern_len + 1;
        }
    }

    return buf_end;
}

const u8 *shiftOrExecBucket(const shift_or_bucket_t *b, const u8 *buf,
                            const u8 *buf_end)
{
    return shiftOrExecBucketWithBitmap(b, buf, buf_end, NULL);
}
