#!/usr/bin/env python3

import argparse
import re
import urllib.parse
from typing import List, Tuple

MAX_PATTERN_LEN = 8
HT_BITS = 9
HT_ENTRIES = 1 << HT_BITS
CUCKOO_TABLE_SIZE = 512
CUCKOO_MAX_EVICT  = 500


class Rule:
    def __init__(self, rule_id, protocol, port, direction, offset, pattern_hex, pattern_bytes):
        self.id = rule_id
        self.protocol = protocol
        self.port = port
        self.direction = direction
        self.offset = offset
        self.pattern_hex = pattern_hex
        self.pattern_bytes = pattern_bytes
        self.length = len(pattern_bytes)


def parse_rule_line(line: str) -> Rule:
    id_match = re.search(r"id=(\d+)", line)
    protocol_match = re.search(r"protocol=(\w+)/(\d+)/(\w+)", line)
    offset_match = re.search(r"offset=(\d+)", line)
    pattern_match = re.search(r"pattern=([%0-9A-Fa-f]+)", line)
    if not all([id_match, protocol_match, offset_match, pattern_match]):
        raise ValueError(f"Failed to parse: {line}")
    rule_id = int(id_match.group(1))
    protocol = protocol_match.group(1)
    port = int(protocol_match.group(2))
    direction = protocol_match.group(3)
    offset = int(offset_match.group(1))
    pattern_hex = pattern_match.group(1)
    pattern_bytes = urllib.parse.unquote(pattern_hex).encode("latin-1")
    return Rule(rule_id, protocol, port, direction, offset, pattern_hex, pattern_bytes)


def parse_all_rules(filename: str) -> List[Rule]:
    rules = []
    with open(filename, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if ":" in line:
                    line = line.split(":", 1)[1].strip()
                rules.append(parse_rule_line(line))
            except Exception:
                pass
    return rules


def get_fast_pattern(pattern_bytes: bytes) -> bytes:
    if len(pattern_bytes) <= MAX_PATTERN_LEN:
        return pattern_bytes
    return pattern_bytes[-MAX_PATTERN_LEN:]


def shift_or_bucket_index(fast_pattern: bytes) -> int:
    mixed = 0x5A
    for i in range(8):
        current_byte = fast_pattern[i] if i < len(fast_pattern) else 0
        rotated = ((mixed & 0x1F) << 3) | ((mixed >> 5) & 0x07)
        mixed = (rotated ^ current_byte) + (i * 17 + 3)
        mixed &= 0xFF
    return mixed & 0x07


def rotate9(value: int, shift: int) -> int:
    shift %= 9
    value &= 0x1FF
    return ((value << shift) | (value >> (9 - shift))) & 0x1FF


def hash_prefix(pattern_bytes: bytes, length: int) -> int:
    hashed = 0
    for index in range(length):
        byte = pattern_bytes[index] if index < len(pattern_bytes) else 0
        hashed ^= rotate9(byte, (index * 3) % 9)
    return hashed & 0x1FF


def build_so_patterns(rules: List[Rule]) -> List[Tuple[int, int, int]]:
    patterns = []
    for rule in rules:
        fp = get_fast_pattern(rule.pattern_bytes)
        len_idx = len(fp) - 1
        pattern_64 = 0
        for i, b in enumerate(fp):
            pattern_64 |= b << ((7 - i) * 8)
        bucket = shift_or_bucket_index(fp)
        patterns.append((pattern_64, bucket, len_idx))
    return patterns


def build_hash_table(rules: List[Rule]) -> List[int]:
    hash_table = [0] * MAX_PATTERN_LEN
    for rule in rules:
        fp = get_fast_pattern(rule.pattern_bytes)
        length = len(fp)
        hashed = hash_prefix(fp, length)
        hash_table[length - 1] |= 1 << hashed
    return hash_table


def cuckoo_hash1(pattern_64: int) -> int:
    h = 0
    for shift in (0, 9, 18, 27, 36, 45, 54):
        h ^= (pattern_64 >> shift) & 0x1FF
    return h


def cuckoo_hash2(pattern_64: int) -> int:
    h = 0
    for i in range(8):
        byte = (pattern_64 >> (56 - i * 8)) & 0xFF
        r = (i * 3) % 9
        rotated = ((byte << r) | (byte >> (9 - r))) & 0x1FF
        h ^= rotated
    return h & 0x1FF


def build_cuckoo_table(rules: List[Rule]):
    tables = [[[None] * CUCKOO_TABLE_SIZE for _ in range(MAX_PATTERN_LEN)]
              for _ in range(2)]
    seen_patterns: List[set] = [set() for _ in range(MAX_PATTERN_LEN)]
    pattern_to_stored_rule = {}
    conflict_rule_ids = set()

    for rule in rules:
        fp = get_fast_pattern(rule.pattern_bytes)
        length = len(fp)
        l = length - 1

        pattern_64 = 0
        for i, b in enumerate(fp):
            pattern_64 |= b << ((7 - i) * 8)

        if pattern_64 in seen_patterns[l]:
            stored_rule = pattern_to_stored_rule[(l, pattern_64)]
            if (stored_rule.protocol != rule.protocol or
                    stored_rule.port != rule.port or
                    stored_rule.direction != rule.direction):
                conflict_rule_ids.add(stored_rule.id)
                print(f"  Conflict: rule {rule.id} "
                      f"({rule.protocol}/{rule.port}/{rule.direction}) shares pattern "
                      f"with stored rule {stored_rule.id} "
                      f"({stored_rule.protocol}/{stored_rule.port}/{stored_rule.direction})"
                      f" -> widening rule {stored_rule.id} port group to wildcard")
            else:
                print(f"  Note: rule {rule.id} shares fast pattern with rule "
                      f"{stored_rule.id} (len={length}, pat=0x{pattern_64:016x}); "
                      f"same port/proto — first rule's ID retained")
            continue
        seen_patterns[l].add(pattern_64)
        pattern_to_stored_rule[(l, pattern_64)] = rule

        cur_table = 0
        cur_pat   = pattern_64
        cur_id    = rule.id
        inserted  = False

        for _ in range(CUCKOO_MAX_EVICT):
            h = cuckoo_hash1(cur_pat) if cur_table == 0 else cuckoo_hash2(cur_pat)
            evicted = tables[cur_table][l][h]
            tables[cur_table][l][h] = (cur_pat, cur_id)
            if evicted is None:
                inserted = True
                break
            cur_pat, cur_id = evicted
            cur_table ^= 1

        if not inserted:
            raise RuntimeError(
                f"Cuckoo insertion failed for rule {rule.id} after "
                f"{CUCKOO_MAX_EVICT} evictions — try larger table or different hash"
            )

    mirrored = 0
    for l in range(MAX_PATTERN_LEN):
        for h in range(CUCKOO_TABLE_SIZE):
            e1 = tables[0][l][h]
            if e1 is not None:
                pat, rid = e1
                h2 = cuckoo_hash2(pat)
                if tables[1][l][h2] is None:
                    tables[1][l][h2] = (pat, rid)
                    mirrored += 1
    print(f"  Mirrored {mirrored} table1 entries into empty table2 h2 slots")

    return tables, conflict_rule_ids


def build_port_groups(rules: List[Rule], conflict_rule_ids: set = None):
    if conflict_rule_ids is None:
        conflict_rule_ids = set()
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
    pg_map   = {}
    pg_specs = []
    rule_pg_list = []

    for rule in rules:
        if rule.id in conflict_rule_ids:
            proto = 0
            src_min, src_max = 0, 65535
            dst_min, dst_max = 0, 65535
        else:
            proto = proto_map.get(rule.protocol.lower(), 0)
            if rule.direction == "request":
                src_min, src_max = 0, 65535
                dst_min, dst_max = rule.port, rule.port
            elif rule.direction == "response":
                src_min, src_max = rule.port, rule.port
                dst_min, dst_max = 0, 65535
            else:
                src_min, src_max = 0, 65535
                dst_min, dst_max = 0, 65535

        key = (proto, src_min, src_max, dst_min, dst_max)
        if key not in pg_map:
            pg_id = len(pg_specs)
            pg_map[key] = pg_id
            pg_specs.append((pg_id, proto, src_min, src_max, dst_min, dst_max))
        pg_id = pg_map[key]
        rule_pg_list.append((rule.id, proto, pg_id, src_min, src_max, dst_min, dst_max))

    return rule_pg_list, pg_specs


def generate_cpp_loader(rules: List[Rule], output_file: str):
    so_patterns  = build_so_patterns(rules)
    hash_table   = build_hash_table(rules)
    cuckoo_tables, conflict_rule_ids = build_cuckoo_table(rules)
    rule_pg_list, pg_specs = build_port_groups(rules, conflict_rule_ids)
    proto_map    = {"tcp": 6, "udp": 17, "icmp": 1}

    with open(output_file, "w") as f:
        f.write("#include <cstdint>\n")
        f.write("#include <cstdio>\n\n")
        f.write(f"#define NUM_RULES          {len(rules)}\n")
        f.write(f"#define FPSM_MAX_PAT_LEN   {MAX_PATTERN_LEN}\n")
        f.write(f"#define FPSM_HT_BITS       {HT_BITS}\n")
        f.write(f"#define FPSM_HT_ENTRIES    {HT_ENTRIES}\n\n")

        f.write("typedef struct { uint32_t patHi; uint32_t patLo; uint8_t bucketLenIdx; } SoPattern;\n")
        f.write(f"static const SoPattern g_soPatterns[{len(rules)}] = {{\n")
        for (pat64, bucket, len_idx) in so_patterns:
            pat_hi = (pat64 >> 32) & 0xFFFFFFFF
            pat_lo =  pat64        & 0xFFFFFFFF
            bucket_len = (bucket << 3) | len_idx
            f.write(f"    {{ 0x{pat_hi:08x}u, 0x{pat_lo:08x}u, 0x{bucket_len:02x} }},\n")
        f.write("};\n\n")

        f.write(f"static const uint64_t g_hashTable[{MAX_PATTERN_LEN}][{HT_ENTRIES // 64}] = {{\n")
        for length in range(MAX_PATTERN_LEN):
            words = []
            for word in range(HT_ENTRIES // 64):
                bits = (hash_table[length] >> (word * 64)) & ((1 << 64) - 1)
                words.append(f"0x{bits:016x}ULL")
            f.write("    { " + ", ".join(words) + " },\n")
        f.write("};\n\n")

        ck_entries = []
        for t in range(2):
            for l in range(MAX_PATTERN_LEN):
                for h in range(CUCKOO_TABLE_SIZE):
                    slot = cuckoo_tables[t][l][h]
                    if slot is not None:
                        pat, rid = slot
                        ck_entries.append((t, l, h, (pat >> 32) & 0xFFFFFFFF,
                                           pat & 0xFFFFFFFF, rid))
        f.write("typedef struct {\n")
        f.write("    uint8_t  tableIdx;\n")
        f.write("    uint8_t  lenIdx;\n")
        f.write("    uint16_t hashIdx;\n")
        f.write("    uint32_t patHi;\n")
        f.write("    uint32_t patLo;\n")
        f.write("    uint16_t ruleId;\n")
        f.write("} CkEntry;\n")
        f.write(f"static const CkEntry g_ckEntries[{len(ck_entries)}] = {{\n")
        for (t, l, h, pat_hi, pat_lo, rid) in ck_entries:
            f.write(f"    {{ {t}, {l}, {h}, 0x{pat_hi:08x}u, 0x{pat_lo:08x}u, {rid} }},\n")
        f.write("};\n\n")

        f.write("typedef struct { uint16_t ruleId; uint8_t proto; uint8_t pgId; uint16_t srcMin; uint16_t srcMax; uint16_t dstMin; uint16_t dstMax; } PgEntry;\n")
        f.write(f"static const PgEntry g_portGroups[{len(rules)}] = {{\n")
        for (rid, proto, pg_id, src_min, src_max, dst_min, dst_max) in rule_pg_list:
            f.write(f"    {{ {rid}, {proto}, {pg_id}, {src_min}, {src_max}, {dst_min}, {dst_max} }},\n")
        f.write("};\n\n")

        f.write("static void loadFPSMShiftOrPatterns() {\n")
        f.write(f'    printf("Loading shift-OR patterns ({len(rules)} rules)...\\n");\n')
        f.write(f"    for (int i = 0; i < {len(rules)}; i++) {{\n")
        f.write("        writeReg(39, g_soPatterns[i].patHi);\n")
        f.write("        writeReg(40, g_soPatterns[i].patLo);\n")
        f.write("        writeReg(41, g_soPatterns[i].bucketLenIdx);\n")
        f.write("    }\n")
        f.write('    printf("Shift-OR patterns loaded.\\n");\n')
        f.write("}\n\n")

        f.write("static void loadFPSMHashTable() {\n")
        f.write(f'    printf("Loading FPSM hash tables ({MAX_PATTERN_LEN} x {HT_ENTRIES})...\\n");\n')
        f.write(f"    for (int l = 0; l < {MAX_PATTERN_LEN}; l++) {{\n")
        f.write(f"        for (int h = 0; h < {HT_ENTRIES}; h++) {{\n")
        f.write("            int word = h / 64;\n")
        f.write("            int bit  = h % 64;\n")
        f.write("            if ((g_hashTable[l][word] >> bit) & 1ULL) {\n")
        f.write("                writeReg(31, ((uint32_t)l << 9) | (uint32_t)h);\n")
        f.write("            }\n")
        f.write("        }\n")
        f.write("    }\n")
        f.write('    printf("Hash table loaded.\\n");\n')
        f.write("}\n\n")

        f.write("static void loadRuleReductionTable() {\n")
        f.write(f'    printf("Loading cuckoo rule table ({len(ck_entries)} entries)...\\n");\n')
        f.write(f"    for (int i = 0; i < {len(ck_entries)}; i++) {{\n")
        f.write("        writeReg(42, g_ckEntries[i].patHi);\n")
        f.write("        writeReg(43, g_ckEntries[i].patLo);\n")
        f.write("        uint32_t ctrl = ((uint32_t)g_ckEntries[i].tableIdx << 28)\n")
        f.write("                      | ((uint32_t)g_ckEntries[i].lenIdx   << 25)\n")
        f.write("                      | ((uint32_t)g_ckEntries[i].hashIdx  << 16)\n")
        f.write("                      |  (uint32_t)g_ckEntries[i].ruleId;\n")
        f.write("        writeReg(32, ctrl);\n")
        f.write("    }\n")
        f.write('    printf("Cuckoo rule table loaded.\\n");\n')
        f.write("}\n\n")

        f.write("static void loadPortGroupTable() {\n")
        f.write(f'    printf("Loading port group table ({len(rules)} rules)...\\n");\n')
        f.write(f"    for (int i = 0; i < {len(rules)}; i++) {{\n")
        f.write("        uint16_t ruleId = g_portGroups[i].ruleId;\n")
        f.write("        uint8_t  proto  = g_portGroups[i].proto;\n")
        f.write("        uint8_t  pgId   = g_portGroups[i].pgId;\n")
        f.write("        uint16_t srcMin = g_portGroups[i].srcMin;\n")
        f.write("        uint16_t srcMax = g_portGroups[i].srcMax;\n")
        f.write("        uint16_t dstMin = g_portGroups[i].dstMin;\n")
        f.write("        uint16_t dstMax = g_portGroups[i].dstMax;\n")
        f.write("        writeReg(33, ((uint32_t)ruleId << 16) | ((uint32_t)pgId << 8) | proto);\n")
        f.write("        writeReg(34, ((uint32_t)srcMin << 16) | srcMax);\n")
        f.write("        writeReg(35, ((uint32_t)dstMin << 16) | dstMax);\n")
        f.write("    }\n")
        f.write('    printf("Port group table loaded.\\n");\n')
        f.write("}\n\n")

        f.write("static void loadAllPatterns() {\n")
        f.write('    printf("Configuring FPSM...\\n");\n')
        f.write("    loadFPSMShiftOrPatterns();\n")
        f.write("    loadFPSMHashTable();\n")
        f.write("    loadRuleReductionTable();\n")
        f.write("    loadPortGroupTable();\n")
        f.write(f'    printf("FPSM configuration complete: %d rules loaded.\\n", NUM_RULES);\n')
        f.write("}\n")


def main():
    parser = argparse.ArgumentParser(description="Generate FPSM pattern loader")
    parser.add_argument("rules_file", nargs="?", default="rule.txt")
    args = parser.parse_args()
    print(f"Parsing rules from {args.rules_file}...")
    rules = parse_all_rules(args.rules_file)
    print(f"Parsed {len(rules)} rules")

    hash_table    = build_hash_table(rules)
    cuckoo_tables, conflict_rule_ids = build_cuckoo_table(rules)
    so_patterns   = build_so_patterns(rules)

    bucket_counts = [0] * 8
    for (_, bucket, _) in so_patterns:
        bucket_counts[bucket] += 1
    print(f"Shift-OR bucket distribution: {bucket_counts}")

    for length in range(MAX_PATTERN_LEN):
        bits_set = bin(hash_table[length]).count("1")
        t0 = sum(1 for h in range(CUCKOO_TABLE_SIZE) if cuckoo_tables[0][length][h] is not None)
        t1 = sum(1 for h in range(CUCKOO_TABLE_SIZE) if cuckoo_tables[1][length][h] is not None)
        print(f"  len={length+1}: FPSM-HT {bits_set}/{HT_ENTRIES} bits set, "
              f"Cuckoo table0={t0}/{CUCKOO_TABLE_SIZE} table1={t1}/{CUCKOO_TABLE_SIZE}")

    output_file = "pattern_loader.h"
    generate_cpp_loader(rules, output_file)
    print(f"\nGenerated {output_file}")


if __name__ == "__main__":
    main()
