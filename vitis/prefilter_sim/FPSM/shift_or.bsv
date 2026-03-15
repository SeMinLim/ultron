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
  method Action insertPattern(Bit#(64) inputPattern, Bit#(3) bucketIdx);
  method Bool bucketHit(Bit#(64) inputWord, Bit#(3) bucketIdx);
  method Bit#(8) bucketBitmap;
endinterface

module mkShiftOr#(Integer patternLenParam)(ShiftOrIfc);
  Reg#(Vector#(8, Vector#(256, Bit#(16)))) shiftMaskByBucket <- mkReg(replicate(replicate(16'hFFFF)));
  Reg#(Bit#(8)) hasPatterns <- mkReg(0);

  method Action insertPattern(Bit#(64) inputPattern, Bit#(3) bucketIdx);
    Vector#(8, Vector#(256, Bit#(16))) newShiftMasks = shiftMaskByBucket;
    Vector#(256, Bit#(16)) bucketMasks = newShiftMasks[bucketIdx];

    for (Integer pos = 0; pos < 8; pos = pos + 1) begin
      if (fromInteger(pos) < fromInteger(patternLenParam)) begin
        Bit#(8) patternByte = getWordByte(inputPattern, pos);
        Bit#(16) bitToClear = ~(16'h1 << fromInteger(pos));
        bucketMasks[patternByte] = bucketMasks[patternByte] & bitToClear;
      end
    end

    newShiftMasks[bucketIdx] = bucketMasks;
    shiftMaskByBucket <= newShiftMasks;
    hasPatterns <= hasPatterns | (8'h1 << bucketIdx);
  endmethod

  method Bool bucketHit(Bit#(64) inputWord, Bit#(3) bucketIdx);
    Bool matchFound = False;

    if (hasPatterns[bucketIdx] == 1'b1 && patternLenParam > 0) begin
      Bit#(16) matchBitPosition = 16'h1 << fromInteger(patternLenParam);
      Bit#(16) state = ~16'h1;
      Vector#(256, Bit#(16)) bucketMasks = shiftMaskByBucket[bucketIdx];

      for (Integer bytePos = 0; bytePos < 8; bytePos = bytePos + 1) begin
        Bit#(8) inputByte = getWordByte(inputWord, bytePos);
        Bit#(16) shiftMask = bucketMasks[inputByte];
        state = ((state << 1) | shiftMask);
        if (fromInteger(bytePos) >= (patternLenParam - 1)) begin
          if ((state & matchBitPosition) == 0) begin
            matchFound = True;
          end
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
