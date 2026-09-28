package shift_or;

import Vector::*;

function Bit#(8) getWordByte(Bit#(64) inputWord, Integer byteIndexFromMsb);
    Integer shiftAmount = (7 - byteIndexFromMsb) * 8;
    return truncate(inputWord >> shiftAmount);
endfunction

function Bit#(3) shiftOrBucketIndex(Bit#(64) inputWord);
    Bit#(8) mixed = 8'h5a;
    for (Integer byteIndex = 0; byteIndex < 8; byteIndex = byteIndex + 1) begin
        Bit#(8) currentByte = getWordByte(inputWord, byteIndex);
        Bit#(8) rotated = {mixed[4:0], mixed[7:5]};
        mixed = (rotated ^ currentByte) + fromInteger((byteIndex * 17) + 3);
    end
    return mixed[2:0];
endfunction

interface ShiftOrIfc;
    method Action  insertPattern(Bit#(64) inputPattern, Bit#(3) bucketIdx);
    method Bool    bucketHit(Bit#(64) inputWord, Bit#(3) bucketIdx);
    method Bit#(8) bucketBitmap;
endinterface

module mkShiftOr#(Integer patternLenParam)(ShiftOrIfc);

    Reg#(Vector#(256, Bit#(64))) shMask <-
        mkReg(replicate(64'hFFFF_FFFF_FFFF_FFFF));

    Reg#(Bit#(8)) hasPatterns <- mkReg(0);

    method Action insertPattern(Bit#(64) inputPattern, Bit#(3) bucketIdx);
        Vector#(256, Bit#(64)) newMask = shMask;
        for (Integer pos = 0; pos < 8; pos = pos + 1) begin
            if (pos < patternLenParam) begin
                Bit#(8)  patByte  = getWordByte(inputPattern, pos);
                Bit#(6)  bitIdx   = fromInteger(pos * 8) + zeroExtend(bucketIdx);
                Bit#(64) clearMsk = ~(64'h1 << bitIdx);
                newMask[patByte]  = newMask[patByte] & clearMsk;
            end
        end
        shMask <= newMask;
        hasPatterns <= hasPatterns | (8'h1 << bucketIdx);
    endmethod

    method Bool bucketHit(Bit#(64) inputWord, Bit#(3) bucketIdx);
        Bool matchFound = False;
        if (hasPatterns[bucketIdx] == 1'b1 && patternLenParam > 0) begin
            Bit#(64) state = 64'hFFFF_FFFF_FFFF_FFFF;
            Bit#(6) matchBit =
                fromInteger((patternLenParam - 1) * 8) + zeroExtend(bucketIdx);

            for (Integer bytePos = 0; bytePos < 8; bytePos = bytePos + 1) begin
                Bit#(8) inputByte = getWordByte(inputWord, bytePos);
                state = (state << 8) | shMask[inputByte];
                if (bytePos >= patternLenParam - 1) begin
                    if (state[matchBit] == 1'b0) matchFound = True;
                end
            end
        end
        return matchFound;
    endmethod

    method Bit#(8) bucketBitmap;
        return hasPatterns;
    endmethod

endmodule

endpackage: shift_or
