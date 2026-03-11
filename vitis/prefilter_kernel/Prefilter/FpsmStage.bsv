package FpsmStage;

import Vector::*;

import CuckooHashTable64::*;
import PrefilterTypes::*;
import PrefilterMatchUtils::*;
import shift_or::*;

interface FpsmStageIfc;
  method Action loadRule(Bit#(PrefilterSlotIdxW) slot, Bit#(64) pattern, Bit#(8) len);
  method PrefilterRuleMask runMatch(Bit#(64) payload64);
  method Bit#(8) bucketBitmap;
endinterface

module mkFpsmStage(FpsmStageIfc);
  Vector#(9, ShiftOrIfc) shiftOrByLen <- genWithM(mkShiftOr);
  Vector#(9, CuckooTable64Ifc#(6)) hashByLen <- replicateM(mkCuckooHashTable64);
  Vector#(9, Reg#(Bool)) stageUsed <- replicateM(mkReg(False));

  method Action loadRule(Bit#(PrefilterSlotIdxW) slot, Bit#(64) pattern, Bit#(8) len);
    if (validPatternLen1to8(len)) begin
      Bit#(4) lenIdx = truncate(len);
      Bit#(64) patternNorm = normalizePatternByLen(pattern, len);
      Bit#(64) key = fnv1a64(patternNorm, len);
      PrefilterRuleMask oldMask = hashByLen[lenIdx].lookupValue(key);
      PrefilterRuleMask slotBit = (64'h1 << slot);
      PrefilterRuleMask newMask = oldMask | slotBit;

      stageUsed[lenIdx] <= True;
      shiftOrByLen[lenIdx].insertPattern(patternNorm);
      hashByLen[lenIdx].insert(key, newMask);
    end
  endmethod

  method PrefilterRuleMask runMatch(Bit#(64) payload64);
    PrefilterRuleMask candidates = 0;

    for (Integer len = 1; len <= 8; len = len + 1) begin
      Bit#(4) lenIdx = fromInteger(len);
      Bit#(8) lenVal = fromInteger(len);

      if (stageUsed[lenIdx]) begin
        for (Integer start = 0; start < 8; start = start + 1) begin
          Bit#(4) startVal = fromInteger(start);
          if ((startVal + truncate(lenVal)) <= 4'd8) begin
            Bit#(64) windowKey = windowKeyByStartLen(payload64, startVal, lenVal);
            if (shiftOrByLen[lenIdx].bucketHit(windowKey)) begin
              Bit#(64) key = fnv1a64(windowKey, lenVal);
              PrefilterRuleMask slotMask = hashByLen[lenIdx].lookupValue(key);
              candidates = candidates | slotMask;
            end
          end
        end
      end
    end

    return candidates;
  endmethod

  method Bit#(8) bucketBitmap;
    Bit#(8) bitmap = 0;
    for (Integer len = 1; len <= 8; len = len + 1) begin
      Bit#(4) lenIdx = fromInteger(len);
      if (stageUsed[lenIdx]) begin
        bitmap = bitmap | shiftOrByLen[lenIdx].bucketBitmap;
      end
    end
    return bitmap;
  endmethod
endmodule

endpackage: FpsmStage
