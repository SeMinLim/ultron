#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>
#include <array>

#include "rule_loader.h"
#include "xrt/xrt_bo.h"
#include "xrt/xrt_device.h"
#include "xrt/xrt_kernel.h"
#include <experimental/xrt_xclbin.h>

static const size_t kBufBytes = 4096;

struct PcapPacket {
  std::array<uint8_t, 64> bytes;
};

static bool read_u32_le(std::ifstream& f, uint32_t* out) {
  uint8_t b[4];
  if (!f.read(reinterpret_cast<char*>(b), 4)) return false;
  *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
  return true;
}

static bool read_u32_be(std::ifstream& f, uint32_t* out) {
  uint8_t b[4];
  if (!f.read(reinterpret_cast<char*>(b), 4)) return false;
  *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
  return true;
}

static std::vector<PcapPacket> read_pcap_packets(const std::string& path) {
  std::vector<PcapPacket> out;
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return out;

  uint8_t global_header[24];
  if (!f.read(reinterpret_cast<char*>(global_header), 24)) return out;

  bool little_endian = false;
  const uint8_t* m = global_header;
  if (m[0] == 0xd4 && m[1] == 0xc3 && m[2] == 0xb2 && m[3] == 0xa1) {
    little_endian = true;
  } else if (m[0] == 0xa1 && m[1] == 0xb2 && m[2] == 0xc3 && m[3] == 0xd4) {
    little_endian = false;
  } else if (m[0] == 0x4d && m[1] == 0x3c && m[2] == 0xb2 && m[3] == 0xa1) {
    little_endian = true;
  } else if (m[0] == 0xa1 && m[1] == 0xb2 && m[2] == 0x3c && m[3] == 0x4d) {
    little_endian = false;
  } else {
    return out;
  }

  auto read_u32 = [&](uint32_t* v) {
    return little_endian ? read_u32_le(f, v) : read_u32_be(f, v);
  };

  while (f) {
    uint32_t ts_sec = 0;
    uint32_t ts_usec = 0;
    uint32_t incl_len = 0;
    uint32_t orig_len = 0;
    if (!read_u32(&ts_sec) || !read_u32(&ts_usec) || !read_u32(&incl_len) || !read_u32(&orig_len)) {
      break;
    }
    if (incl_len == 0 || incl_len > 65536) {
      break;
    }

    std::vector<uint8_t> pkt(incl_len);
    if (!f.read(reinterpret_cast<char*>(pkt.data()), incl_len)) {
      break;
    }

    PcapPacket p{};
    size_t copy_len = pkt.size() < p.bytes.size() ? pkt.size() : p.bytes.size();
    for (size_t i = 0; i < copy_len; i++) {
      p.bytes[i] = pkt[i];
    }
    out.push_back(p);
  }

  return out;
}

static void clear_word(uint32_t* words) {
  for (int i = 0; i < 16; i++) {
    words[i] = 0;
  }
}

static void write_load_word(uint32_t* words, const Rule& rule, uint16_t slot) {
  clear_word(words);

  uint64_t rule64 = pattern_to_u64_be(rule.pattern);

  words[2] = (uint32_t)(rule64 & 0xffffffffu);
  words[3] = (uint32_t)((rule64 >> 32) & 0xffffffffu);
  words[4] = (uint32_t)rule.pattern.size();
  words[5] = rule.id;
  words[6] = slot;

  uint32_t pgType = 1;
  uint32_t dirBits = 2;
  if (rule.direction == RuleDirection::Request) dirBits = 0;
  else if (rule.direction == RuleDirection::Response) dirBits = 1;
  words[7] = (pgType & 0x3u) | ((uint32_t)rule.port << 2) | (dirBits << 27);
  words[8] = (uint32_t)rule.port;
  words[9] = 0;
  words[10] = 0;
}

static void write_dummy_load_word(uint32_t* words, uint16_t slot) {
  clear_word(words);
  uint64_t dummyRule = 0x7f00000000000000ULL;
  words[2] = (uint32_t)(dummyRule & 0xffffffffu);
  words[3] = (uint32_t)((dummyRule >> 32) & 0xffffffffu);
  words[4] = 1;
  words[5] = 0;
  words[6] = slot;
  uint32_t pgType = 1;
  uint32_t dirBits = 2;
  words[7] = (pgType & 0x3u) | (dirBits << 27);
  words[8] = 0;
  words[9] = 0;
  words[10] = 0;
}

static void write_packet_word(uint8_t* dst, const PcapPacket& packet) {
  std::memset(dst, 0, 64);
  for (size_t i = 0; i < packet.bytes.size(); i++) {
    dst[i] = packet.bytes[i];
  }
}

int main(int argc, char** argv) {
  std::string xclbin = "../../hw/hw/kernel.xclbin";
  std::string rulePath = "../../rule.txt";
  std::string pcapPath = "../../OrangeScrum OrangeScrum filename XSS.pcap";

  if (argc >= 2) {
    xclbin = argv[1];
  }
  if (argc >= 3) {
    rulePath = argv[2];
  }
  if (argc >= 4) {
    pcapPath = argv[3];
  }

  if (argc > 4) {
    std::fprintf(stderr, "usage: %s [kernel.xclbin] [rule.txt] [input.pcap]\n", argv[0]);
    return 2;
  }

  std::vector<Rule> rules = load_rules_for_kernel(rulePath);
  if (rules.empty()) {
    std::fprintf(stderr, "no loadable rules found for kernel model in %s\n", rulePath.c_str());
    return 2;
  }

  std::vector<PcapPacket> packets = read_pcap_packets(pcapPath);
  if (packets.empty()) {
    std::fprintf(stderr, "no packets decoded from pcap %s\n", pcapPath.c_str());
    return 2;
  }

  const size_t slotCount = 64;
  size_t batchCount = (rules.size() + slotCount - 1) / slotCount;
  if (batchCount == 0) batchCount = 1;

  std::printf("loaded_rules=%zu packets=%zu batches=%zu\n", rules.size(), packets.size(), batchCount);

  auto device = xrt::device(0);
  auto uuid = device.load_xclbin(xclbin);
  auto kernel = xrt::kernel(device, uuid, "kernel:{kernel_1}");

  auto boIn = xrt::bo(device, kBufBytes, kernel.group_id(1));
  auto boOut = xrt::bo(device, kBufBytes, kernel.group_id(2));
  auto inWords = boIn.map<uint32_t*>();
  auto inBytes = boIn.map<uint8_t*>();
  auto outWords = boOut.map<uint32_t*>();

  std::fill(inWords, inWords + (kBufBytes / 4), 0);
  std::fill(outWords, outWords + (kBufBytes / 4), 0);
  boOut.sync(XCL_BO_SYNC_BO_TO_DEVICE);

  std::vector<bool> packetHit(packets.size(), false);
  std::vector<uint32_t> packetRuleId(packets.size(), 0);
  std::set<uint32_t> matchedRuleIds;

  uint32_t parsedSupportedPackets = 0;

  for (size_t batch = 0; batch < batchCount; batch++) {
    size_t base = batch * slotCount;

    for (size_t slot = 0; slot < slotCount; slot++) {
      size_t idx = base + slot;
      if (idx < rules.size()) {
        write_load_word(inWords, rules[idx], (uint16_t)slot);
      } else {
        write_dummy_load_word(inWords, (uint16_t)slot);
      }

      boIn.sync(XCL_BO_SYNC_BO_TO_DEVICE);
      auto loadRun = kernel((uint32_t)0, boIn, boOut);
      loadRun.wait();
      boOut.sync(XCL_BO_SYNC_BO_FROM_DEVICE);
    }

    for (size_t pktIdx = 0; pktIdx < packets.size(); pktIdx++) {
      write_packet_word(inBytes, packets[pktIdx]);
      boIn.sync(XCL_BO_SYNC_BO_TO_DEVICE);
      auto matchRun = kernel((uint32_t)1, boIn, boOut);
      matchRun.wait();
      boOut.sync(XCL_BO_SYNC_BO_FROM_DEVICE);

      bool parserSupported = ((outWords[13] >> 1) & 1u) != 0;
      if (parserSupported) {
        parsedSupportedPackets++;
      }

      uint32_t hit = outWords[7] & 1u;
      if (hit && !packetHit[pktIdx]) {
        packetHit[pktIdx] = true;
        packetRuleId[pktIdx] = outWords[5];
        matchedRuleIds.insert(outWords[5]);
      }
    }
  }

  size_t matchedPackets = 0;
  for (size_t i = 0; i < packetHit.size(); i++) {
    if (packetHit[i]) {
      matchedPackets++;
      std::printf("pkt=%zu matched rule_id=%u\n", i, packetRuleId[i]);
    }
  }

  std::printf("summary packets=%zu matched_packets=%zu matched_rules=%zu parser_supported_events=%u load=%u match=%u hit=%u\n",
              packets.size(),
              matchedPackets,
              matchedRuleIds.size(),
              parsedSupportedPackets,
              outWords[0],
              outWords[1],
              outWords[2]);

  return 0;
}
