#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../obj/verilog"

EXPECTED=81   # 4 payload + 12 bloom (4 lanes x k=3) + 64 cuckoo banks + 1 assigns table

perl -0777 -i -pe \
  's/BRAM2(\s*\#\((?:[^()]|\([^()]*\))*\)\s*)(kernelMain_exactMatch_eng\d+_payloadTbl_memory|bloom_\d+_\d+_memory|banks_\d+_ram_memory|assignsTbl_memory)\(/BRAM2Block$1$2(/g' \
  kernel.v mkGramMatcher.v

n=$(grep -ch 'BRAM2Block #' kernel.v mkGramMatcher.v | awk '{s+=$1} END{print s+0}')

if [ "$n" -ne "$EXPECTED" ]; then
    echo "ERROR [force_block_ram]: rewrote $n instances, expected $EXPECTED." >&2
    echo "  The engine or bloom-lane counts changed -- update EXPECTED and" >&2
    echo "  re-check the URAM budget before building." >&2
    exit 1
fi

echo "INFO [force_block_ram]: $n memories moved to BRAM2Block (payload + bloom + cuckoo + assigns)"
