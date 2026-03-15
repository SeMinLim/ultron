package RuleReduction;

import Vector::*;

typedef 256 InputWidth;
typedef 8   MaxReduced;

function Bit#(32) countMatches(Vector#(InputWidth, Bool) fpsmBits);
    Bit#(32) total = 0;
    for (Integer i = 0; i < valueOf(InputWidth); i = i + 1) begin
        if (fpsmBits[i]) begin
            total = total + 1;
        end
    end
    return total;
endfunction

function Bit#(32) reduceMatchCount(Vector#(InputWidth, Bool) fpsmBits);
    Bit#(32) count = countMatches(fpsmBits);
    return (count > 8) ? 8 : count;
endfunction

endpackage: RuleReduction
