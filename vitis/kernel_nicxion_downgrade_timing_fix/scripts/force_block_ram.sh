#!/bin/bash
# Force the ExactMatch payload buffers and the bloom filter copies onto block RAM.
#
# WHY: every bsc-generated memory instantiates the same BRAM2 primitive, so RAM
# style cannot be selected per instance from BSV.  Vivado then infers URAM for
# anything wide/deep enough, and on the target card the URAM budget (50) is the
# binding constraint:
#
#     bitmaps 3 x NBitmapLanes(16) = 48 URAM   <- must stay in URAM
#     payload 4 engines x 8        = 32 URAM   <- moved here to BRAM
#     bloom   12 copies            = 12 URAM   <- moved here to BRAM
#     cuckoo  64 banks             =  0 URAM   <- pinned here too: at read
#             latency 2 (250 MHz) a pipelined 1024x44 memory is a URAM
#             candidate, and 64 of them would blow the budget
#     assigns  1 table (8192x96)   =  0 URAM   <- pinned for the same reason
#     pkt buf  1 (256x519)         =  0 URAM   <- store-and-forward reader buffer
#
# BRAM2Block.v (kernel dir) is a copy of the bsc Vivado primitive that carries
# (* RAM_STYLE = "BLOCK" *); this script repoints only the instances above at
# it.  Only the bitmap lanes keep using BRAM2, so Vivado's normal inference
# still gives the bitmaps their URAMs.
#
# Runs from the makefile after bsc + the verilog copies, before XO packaging.
set -euo pipefail

cd "$(dirname "$0")/../obj/verilog"

EXPECTED=82   # 4 payload + 12 bloom (4 lanes x k=3) + 64 cuckoo banks + 1 assigns table + 1 packet buffer

perl -0777 -i -pe \
  's/BRAM2(\s*\#\((?:[^()]|\([^()]*\))*\)\s*)(kernelMain_exactMatch_eng\d+_payloadTbl_memory|bloom_\d+_\d+_memory|banks_\d+_ram_memory|assignsTbl_memory|kernelMain_pktReader_dataQ_memory)\(/BRAM2Block$1$2(/g' \
  kernel.v mkGramMatcher.v

n=$(grep -ch 'BRAM2Block #' kernel.v mkGramMatcher.v | awk '{s+=$1} END{print s+0}')

if [ "$n" -ne "$EXPECTED" ]; then
    echo "ERROR [force_block_ram]: rewrote $n instances, expected $EXPECTED." >&2
    echo "  The engine or bloom-lane counts changed -- update EXPECTED and" >&2
    echo "  re-check the URAM budget before building." >&2
    exit 1
fi

echo "INFO [force_block_ram]: $n memories moved to BRAM2Block (payload + bloom + cuckoo + assigns + pkt buffer)"
