package RuleReductionStage;

import PrefilterTypes::*;

function PrefilterRuleMask reduceMaskToN(PrefilterRuleMask inMask, Integer keepCount);
  PrefilterRuleMask outMask = 0;
  UInt#(8) kept = 0;
  UInt#(8) keepLimit = fromInteger(keepCount);

  for (Integer slot = 0; slot < valueOf(PrefilterRuleSlots); slot = slot + 1) begin
    if (inMask[slot] == 1'b1 && kept < keepLimit) begin
      outMask = outMask | (64'h1 << fromInteger(slot));
      kept = kept + 1;
    end
  end

  return outMask;
endfunction

interface RuleReductionStageIfc;
  method PrefilterRuleMask reduce64to8(PrefilterRuleMask inMask);
  method PrefilterRuleMask reduce8to2(PrefilterRuleMask inMask);
endinterface

module mkRuleReductionStage(RuleReductionStageIfc);
  method PrefilterRuleMask reduce64to8(PrefilterRuleMask inMask);
    return reduceMaskToN(inMask, 8);
  endmethod

  method PrefilterRuleMask reduce8to2(PrefilterRuleMask inMask);
    return reduceMaskToN(inMask, 2);
  endmethod
endmodule

endpackage: RuleReductionStage
