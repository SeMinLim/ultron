package shift_or;

import Vector::*;

// Extract byte 'byteIndexFromMsb' (0=MSB) from a 64-bit word
function Bit#(8) getWordByte(Bit#(64) inputWord, Integer byteIndexFromMsb);
    Integer shiftAmount = (7 - byteIndexFromMsb) * 8;
    return truncate(inputWord >> shiftAmount);
endfunction

// ── Transposed shMask storage ─────────────────────────────────────────────────
//
// Original layout: shMask[char] = Bit#(64)
//   Reading it at runtime creates a 256→64-bit mux (2752 LUTs) per call.
//   With 32 lanes × 8 lengths × 8 buckets × 8 bytePos = 16 384 reads → ~1.5 M LUTs.
//
// Transposed layout: charBits[j] = Bit#(256), where bit c = 1 iff char c matches
//   NFA position j (= p*8+b for byte-position p and bucket b).
//   Reading charBits[j][char] is a 256→1-bit mux (43 LUTs).
//   Same 16 384 reads now cost 9 216 × 43 ≈ 396 K LUTs — fits comfortably.
//
// Loading: loadShMaskEntry(charIdx, maskVal) sets charBits[j][charIdx] = 1
//   for every j where maskVal[j] == 0 (i.e. char charIdx matches NFA position j).

interface ShiftOrIfc;
    method Action  loadShMaskEntry(Bit#(8) charIdx, Bit#(64) maskVal);
    method Action  loadHasPatterns(Bit#(8) bitmap);
    method Bool    bucketHit(Bit#(64) inputWord, Bit#(3) bucketIdx);
    method Bit#(8) bucketBitmap;
endinterface

module mkShiftOr#(Integer patternLenParam)(ShiftOrIfc);

    // 64 bit-planes: charBits[p*8+b][c] = 1 iff character c matches
    // byte-position p for bucket b.  All start as 0 (no matches loaded).
    Vector#(64, Reg#(Bit#(256))) charBits <- replicateM(mkReg(0));

    Reg#(Bit#(8)) hasPatterns <- mkReg(0);

    // ── Load ─────────────────────────────────────────────────────────────────
    // For each of the 64 NFA bit positions j: if maskVal[j] == 0, the
    // character charIdx matches position j → set charBits[j][charIdx].
    method Action loadShMaskEntry(Bit#(8) charIdx, Bit#(64) maskVal);
        Bit#(256) one256 = 1;
        Bit#(256) bit_pos = one256 << charIdx;   // one-hot at charIdx position
        for (Integer j = 0; j < 64; j = j + 1) begin
            Bool matches = (maskVal[fromInteger(j)] == 1'b0);
            charBits[j] <= matches ? (charBits[j] | bit_pos) : charBits[j];
        end
    endmethod

    method Action loadHasPatterns(Bit#(8) bitmap);
        hasPatterns <= bitmap;
    endmethod

    // ── Match ─────────────────────────────────────────────────────────────────
    // Check whether inputWord (8 bytes starting at a lane) matches the
    // pattern of length patternLenParam for bucket bucketIdx.
    //
    // For byte-position p (0..patternLenParam-1):
    //   byteVal = inputWord byte p
    //   hit = hit AND charBits[p*8+bucketIdx][byteVal]
    //
    // Each charBits[j] read is a 256→1-bit mux (43 LUTs).
    // When called from FPSM with bucketIdx = fromInteger(b) (static constant),
    // the inner 8-way select below reduces to a direct wire (0 extra LUTs).
    method Bool bucketHit(Bit#(64) inputWord, Bit#(3) bucketIdx);
        Bool matchFound = False;
        if (hasPatterns[bucketIdx] == 1'b1 && patternLenParam > 0) begin
            Bool hit = True;
            for (Integer p = 0; p < 8; p = p + 1) begin
                if (p < patternLenParam) begin
                    Bit#(8) byteVal = getWordByte(inputWord, p);

                    // Select charBits[p*8 + bucketIdx].
                    // For static bucketIdx (fromInteger call) Vivado constant-folds this.
                    Bit#(256) col = 0;
                    for (Integer bb = 0; bb < 8; bb = bb + 1)
                        if (bucketIdx == fromInteger(bb))
                            col = charBits[p * 8 + bb];

                    // 256:1 1-bit mux – the cheap read at runtime
                    if (col[byteVal] == 1'b0) hit = False;
                end
            end
            matchFound = hit;
        end
        return matchFound;
    endmethod

    method Bit#(8) bucketBitmap;
        return hasPatterns;
    endmethod

endmodule

endpackage: shift_or
