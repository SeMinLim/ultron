package FPSM;

import Vector::*;
import shift_or::*;

typedef 32 NumLanes;
typedef 8  BytesPerLane;
typedef TMul#(NumLanes, BytesPerLane) OutputSize;

function Bit#(8) getByte(Bit#(256) payload, Integer i);
    Integer half = (i / 16) * 128;
    Integer pos  = i % 16;
    Integer lo   = half + (15 - pos) * 8;
    return payload[lo + 7 : lo];
endfunction

function Bit#(9) hashBytes(Bit#(256) payload, Integer k, Integer len);
    Bit#(9) h = 0;
    for (Integer i = 0; i < 8; i = i + 1)
        if (i < len && k + i < 32) begin
            Bit#(9) b = zeroExtend(getByte(payload, k + i));
            Integer r = (i * 3) % 9;
            h = h ^ ((b << fromInteger(r)) | (b >> fromInteger(9 - r)));
        end
    return h;
endfunction

interface FPSMIfc;
    // Fully combinational: shift-OR NFA AND bloom-filter hash run in parallel
    // for all 32 lanes simultaneously; returns 256-bit match vector in 1 cycle.
    method Vector#(OutputSize, Bool) process(Bit#(256) payload);
    method Action loadHTBit(Bit#(3) lenIdx, Bit#(9) hashIdx);
    method Action loadShMaskEntry(Bit#(3) lenIdx, Bit#(8) charIdx, Bit#(64) maskVal);
    method Action loadHasPatterns(Bit#(3) lenIdx, Bit#(8) bitmap);
    method Bit#(8) soBitmap;
endinterface

(* synthesize *)
module mkFPSM(FPSMIfc);

    // One ShiftOr NFA per pattern length 1..8
    // shift_or.bsv now uses transposed charBits storage:
    //   charBits[j][c] = 1-bit match flag  →  256→1-bit mux (43 LUTs) per read
    //   vs old shMask[c] = 64-bit column   →  256→64-bit mux (2752 LUTs) per read
    // Total LUTs: ~396 K vs ~1.5 M with old layout.
    Vector#(8, ShiftOrIfc) soMatchers;
    soMatchers[0] <- mkShiftOr(1);
    soMatchers[1] <- mkShiftOr(2);
    soMatchers[2] <- mkShiftOr(3);
    soMatchers[3] <- mkShiftOr(4);
    soMatchers[4] <- mkShiftOr(5);
    soMatchers[5] <- mkShiftOr(6);
    soMatchers[6] <- mkShiftOr(7);
    soMatchers[7] <- mkShiftOr(8);

    // Bloom-filter hash tables, one per length (512-entry bitvector)
    Vector#(8, Reg#(Bit#(512))) hashTables <- replicateM(mkReg(0));

    // ── Main matching: all 32 lanes in parallel, 1 cycle ─────────────────────
    // For each lane k (0..31) and length l (0..7):
    //   soHit  = OR of 8 NFA bucket results  (shift-OR pre-loaded shMask)
    //   hashHit = hashTables[l][hash(payload, k, l+1)]
    //   result[k*8+l] = soHit AND hashHit
    // Output: 256-bit match vector fed to RuleReduction.
    method Vector#(OutputSize, Bool) process(Bit#(256) payload);
        Bit#(256) result = 0;

        for (Integer k = 0; k < 32; k = k + 1) begin
            Bit#(64) laneWord = {
                getByte(payload, k+0), getByte(payload, k+1),
                getByte(payload, k+2), getByte(payload, k+3),
                getByte(payload, k+4), getByte(payload, k+5),
                getByte(payload, k+6), getByte(payload, k+7)
            };

            for (Integer l = 0; l < 8; l = l + 1) begin
                // Shift-OR: OR across all 8 buckets
                Bool shiftOrHit = False;
                for (Integer b = 0; b < 8; b = b + 1)
                    if (soMatchers[l].bucketHit(laneWord, fromInteger(b)))
                        shiftOrHit = True;

                // Bloom-filter hash
                Bit#(9) h       = hashBytes(payload, k, l + 1);
                Bool    hashHit = (hashTables[l][h] == 1'b1);

                // AND: both must agree
                if (shiftOrHit && hashHit)
                    result[k * 8 + l] = 1;
            end
        end

        return unpack(result);
    endmethod

    method Action loadHTBit(Bit#(3) lenIdx, Bit#(9) hashIdx);
        Bit#(512) one512  = 1;
        Bit#(512) bit_pos = one512 << hashIdx;
        case (lenIdx)
            3'd0: hashTables[0] <= hashTables[0] | bit_pos;
            3'd1: hashTables[1] <= hashTables[1] | bit_pos;
            3'd2: hashTables[2] <= hashTables[2] | bit_pos;
            3'd3: hashTables[3] <= hashTables[3] | bit_pos;
            3'd4: hashTables[4] <= hashTables[4] | bit_pos;
            3'd5: hashTables[5] <= hashTables[5] | bit_pos;
            3'd6: hashTables[6] <= hashTables[6] | bit_pos;
            3'd7: hashTables[7] <= hashTables[7] | bit_pos;
        endcase
    endmethod

    method Action loadShMaskEntry(Bit#(3) lenIdx, Bit#(8) charIdx, Bit#(64) maskVal);
        case (lenIdx)
            3'd0: soMatchers[0].loadShMaskEntry(charIdx, maskVal);
            3'd1: soMatchers[1].loadShMaskEntry(charIdx, maskVal);
            3'd2: soMatchers[2].loadShMaskEntry(charIdx, maskVal);
            3'd3: soMatchers[3].loadShMaskEntry(charIdx, maskVal);
            3'd4: soMatchers[4].loadShMaskEntry(charIdx, maskVal);
            3'd5: soMatchers[5].loadShMaskEntry(charIdx, maskVal);
            3'd6: soMatchers[6].loadShMaskEntry(charIdx, maskVal);
            3'd7: soMatchers[7].loadShMaskEntry(charIdx, maskVal);
        endcase
    endmethod

    method Action loadHasPatterns(Bit#(3) lenIdx, Bit#(8) bitmap);
        case (lenIdx)
            3'd0: soMatchers[0].loadHasPatterns(bitmap);
            3'd1: soMatchers[1].loadHasPatterns(bitmap);
            3'd2: soMatchers[2].loadHasPatterns(bitmap);
            3'd3: soMatchers[3].loadHasPatterns(bitmap);
            3'd4: soMatchers[4].loadHasPatterns(bitmap);
            3'd5: soMatchers[5].loadHasPatterns(bitmap);
            3'd6: soMatchers[6].loadHasPatterns(bitmap);
            3'd7: soMatchers[7].loadHasPatterns(bitmap);
        endcase
    endmethod

    method Bit#(8) soBitmap;
        Bit#(8) bm = 0;
        for (Integer l = 0; l < 8; l = l + 1)
            bm = bm | soMatchers[l].bucketBitmap;
        return bm;
    endmethod

endmodule

endpackage: FPSM
