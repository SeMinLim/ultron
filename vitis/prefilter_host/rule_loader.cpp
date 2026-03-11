#include "rule_loader.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

static std::string trim(const std::string& s) {
  size_t begin = 0;
  while (begin < s.size() && std::isspace((unsigned char)s[begin])) {
    begin++;
  }
  size_t end = s.size();
  while (end > begin && std::isspace((unsigned char)s[end - 1])) {
    end--;
  }
  return s.substr(begin, end - begin);
}

static bool parse_u32(const std::string& s, uint32_t* out) {
  if (!out || s.empty()) return false;
  char* end = nullptr;
  unsigned long v = std::strtoul(s.c_str(), &end, 10);
  if (end == s.c_str() || *end != '\0') return false;
  *out = static_cast<uint32_t>(v);
  return true;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static std::vector<uint8_t> decode_percent_bytes(const std::string& encoded) {
  std::vector<uint8_t> out;
  out.reserve(encoded.size());
  for (size_t i = 0; i < encoded.size(); i++) {
    if (encoded[i] == '%' && i + 2 < encoded.size()) {
      int hi = hex_nibble(encoded[i + 1]);
      int lo = hex_nibble(encoded[i + 2]);
      if (hi >= 0 && lo >= 0) {
        uint8_t b = static_cast<uint8_t>((hi << 4) | lo);
        if (b >= 'A' && b <= 'Z') b = static_cast<uint8_t>(b + ('a' - 'A'));
        out.push_back(b);
        i += 2;
        continue;
      }
    }
    uint8_t b = static_cast<uint8_t>(encoded[i]);
    if (b >= 'A' && b <= 'Z') b = static_cast<uint8_t>(b + ('a' - 'A'));
    out.push_back(b);
  }
  return out;
}

static bool split_field(const std::string& line, const std::string& key, std::string* out) {
  if (!out) return false;
  size_t pos = line.find(key);
  if (pos == std::string::npos) return false;
  pos += key.size();
  size_t end = line.find(' ', pos);
  if (end == std::string::npos) end = line.size();
  *out = line.substr(pos, end - pos);
  return true;
}

static bool parse_rule(const std::string& line, Rule* out) {
  if (!out) return false;
  std::string idField, protoField, offsetField, patternField;
  if (!split_field(line, "id=", &idField) ||
      !split_field(line, "protocol=", &protoField) ||
      !split_field(line, "offset=", &offsetField) ||
      !split_field(line, "pattern=", &patternField)) {
    return false;
  }
  uint32_t id = 0;
  if (!parse_u32(idField, &id)) return false;

  size_t slash1 = protoField.find('/');
  size_t slash2 = protoField.find('/', slash1 == std::string::npos ? std::string::npos : slash1 + 1);
  if (slash1 == std::string::npos || slash2 == std::string::npos) return false;

  std::string protoName = protoField.substr(0, slash1);
  std::string portText = protoField.substr(slash1 + 1, slash2 - slash1 - 1);
  std::string dirText = protoField.substr(slash2 + 1);
  std::transform(protoName.begin(), protoName.end(), protoName.begin(), ::tolower);
  std::transform(dirText.begin(), dirText.end(), dirText.begin(), ::tolower);

  uint8_t proto = 0;
  if (protoName == "tcp") {
    proto = static_cast<uint8_t>(PacketProtocol::Tcp);
  } else if (protoName == "udp") {
    proto = static_cast<uint8_t>(PacketProtocol::Udp);
  } else if (protoName == "icmp") {
    proto = static_cast<uint8_t>(PacketProtocol::Icmp);
  } else {
    uint32_t p = 0;
    if (!parse_u32(protoName, &p) || p > 255) return false;
    proto = static_cast<uint8_t>(p);
  }

  uint32_t port32 = 0;
  if (!parse_u32(portText, &port32) || port32 > 65535) return false;
  uint16_t port = static_cast<uint16_t>(port32);

  RuleDirection direction = RuleDirection::Any;
  if (dirText == "request") direction = RuleDirection::Request;
  else if (dirText == "response") direction = RuleDirection::Response;

  std::string offsetHead = offsetField;
  size_t slash = offsetHead.find('/');
  if (slash != std::string::npos) offsetHead = offsetHead.substr(0, slash);
  uint32_t offset = 0;
  if (!parse_u32(offsetHead, &offset)) return false;

  std::vector<uint8_t> pattern = decode_percent_bytes(patternField);
  if (pattern.empty()) return false;

  out->id = id;
  out->proto = proto;
  out->port = port;
  out->direction = direction;
  out->offset = offset;
  out->pattern = pattern;
  return true;
}

std::vector<Rule> load_rules_for_kernel(const std::string& path) {
  std::vector<Rule> loaded;
  std::ifstream in(path.c_str());
  if (!in.is_open()) return loaded;

  std::string line;
  const size_t kMaxRules = 65535;
  while (std::getline(in, line) && loaded.size() < kMaxRules) {
    Rule rule;
    std::string t = trim(line);
    if (t.empty()) continue;
    if (!parse_rule(t, &rule)) continue;

    if (rule.id >= 65536) continue;
    if (rule.pattern.empty()) continue;
    if (rule.pattern.size() > 64) continue;
    if (rule.pattern.size() > 8) {
      rule.pattern.resize(8);
    }
    if (rule.proto != static_cast<uint8_t>(PacketProtocol::Tcp) &&
        rule.proto != static_cast<uint8_t>(PacketProtocol::Udp) &&
        rule.proto != static_cast<uint8_t>(PacketProtocol::Icmp)) {
      continue;
    }
    loaded.push_back(rule);
  }
  return loaded;
}

uint64_t pattern_to_u64_be(const std::vector<uint8_t>& pattern) {
  uint8_t bytes[8] = {0};
  for (size_t i = 0; i < pattern.size() && i < 8; i++) {
    bytes[i] = pattern[i];
  }
  return ((uint64_t)bytes[0] << 56) |
         ((uint64_t)bytes[1] << 48) |
         ((uint64_t)bytes[2] << 40) |
         ((uint64_t)bytes[3] << 32) |
         ((uint64_t)bytes[4] << 24) |
         ((uint64_t)bytes[5] << 16) |
         ((uint64_t)bytes[6] << 8) |
         (uint64_t)bytes[7];
}
