#ifndef PORT_OFFSET_MATCHER_H
#define PORT_OFFSET_MATCHER_H

#include "exact_match.h"
#include "rule_loader.h"
#include "packet_parser.h"

int port_offset_match(const MatchResult *matches, int nm,
                      const RuleSet *rs,
                      const Packet *pkt,
                      MatchResult *out, int out_max);

#endif
