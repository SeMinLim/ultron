#include "pm_output.h"

int pm_output(const MatchResult *matches, int nm,
              uint8_t *out, int out_max)
{
    int written = 0;

    for (int i = 0; i < nm; i++) {
        if (written + 2 > out_max)
            break;
        uint16_t id = (uint16_t)matches[i].rule_id;
        out[written++] = (uint8_t)(id >> 8);
        out[written++] = (uint8_t)(id & 0xFF);
    }

    return written;
}
