#ifndef PM_OUTPUT_H
#define PM_OUTPUT_H

#include <stdint.h>
#include "exact_match.h"

int pm_output(const MatchResult *matches, int nm,
              uint8_t *out, int out_max);

#endif
