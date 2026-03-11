#ifndef PREFILTER_HOST_RULE_LOADER_H
#define PREFILTER_HOST_RULE_LOADER_H

#include <cstdint>
#include <string>
#include <vector>

enum class RuleDirection { Any, Request, Response };

enum class PacketProtocol : uint8_t {
  Tcp = 6,
  Udp = 17,
  Icmp = 1
};

struct Rule {
  uint32_t id;
  uint8_t proto;
  uint16_t port;
  RuleDirection direction;
  uint32_t offset;
  std::vector<uint8_t> pattern;
};

std::vector<Rule> load_rules_for_kernel(const std::string& path);
uint64_t pattern_to_u64_be(const std::vector<uint8_t>& pattern);

#endif
