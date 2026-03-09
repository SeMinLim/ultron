package RuleReductionStage;

function Bit#(64) reduceMask64ToN(Bit#(64) inMask, Integer keepCount);
  Bit#(64) outMask = 0;
  UInt#(7) kept = 0;
  UInt#(7) keepLimit = fromInteger(keepCount);

  for (Integer slot = 0; slot < 64; slot = slot + 1) begin
    if (inMask[slot] == 1'b1 && kept < keepLimit) begin
      outMask = outMask | (64'h1 << fromInteger(slot));
      kept = kept + 1;
    end
  end

  return outMask;
endfunction

interface RuleReductionStageIfc;
  method Bit#(64) reduce64to8(Bit#(64) inMask);
  method Bit#(64) reduce8to2(Bit#(64) inMask);
endinterface

module mkRuleReductionStage(RuleReductionStageIfc);
  method Bit#(64) reduce64to8(Bit#(64) inMask);
    return reduceMask64ToN(inMask, 8);
  endmethod

  method Bit#(64) reduce8to2(Bit#(64) inMask);
    return reduceMask64ToN(inMask, 2);
  endmethod
endmodule

endpackage: RuleReductionStage
