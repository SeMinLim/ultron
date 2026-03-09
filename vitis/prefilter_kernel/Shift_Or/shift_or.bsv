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
  method Action insertPattern(Bit#(64) inputPattern);
  method Bool bucketHit(Bit#(64) inputWord);
  method Bit#(8) bucketBitmap;
endinterface

module mkShiftOr#(Integer patternLenParam)(ShiftOrIfc);
  Reg#(Vector#(256, Bit#(16))) mask <- mkReg(replicate(16'hFFFF));
  Reg#(Bool) hasPatterns <- mkReg(False);

  method Action insertPattern(Bit#(64) inputPattern);
    Vector#(256, Bit#(16)) newMask = mask;
    for (Integer i = 0; i < 8; i = i + 1) begin
      if (fromInteger(i) < fromInteger(patternLenParam)) begin
        Bit#(8) byteVal = getWordByte(inputPattern, i);
        Bit#(16) clearBit = ~(16'h1 << fromInteger(i));
        newMask[byteVal] = newMask[byteVal] & clearBit;
      end
    end
    mask <= newMask;
    hasPatterns <= True;
  endmethod

  method Bool bucketHit(Bit#(64) inputWord);
    Bool result = False;
    if (hasPatterns && patternLenParam > 0) begin
      Bit#(16) matchBit = 16'h1 << fromInteger(patternLenParam);
      Bit#(16) state = ~16'h1;
      for (Integer i = 0; i < 8; i = i + 1) begin
        Bit#(8) b = getWordByte(inputWord, i);
        Bit#(16) m = mask[b];
        state = (state | m) << 1;
        if (fromInteger(i) >= patternLenParam - 1 && (state & matchBit) == 0) begin
          result = True;
        end
      end
    end
    return result;
  endmethod

  method Bit#(8) bucketBitmap;
    return hasPatterns ? 8'h1 : 8'h0;
  endmethod
endmodule

endpackage: shift_or
