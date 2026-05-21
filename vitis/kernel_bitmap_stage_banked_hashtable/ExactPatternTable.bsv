package ExactPatternTable;

import BRAMCore::*;
import FIFOF::*;
import SpecialFIFOs::*;
import Vector::*;

// 64K x 512b pattern store as 16 URAM tiles indexed by ruleId[3:0].
// NReadPorts independent read ports run in parallel: port g owns the tiles
// whose index has low 2 bits == g, so no tile is shared between ports and
// pattern data is never duplicated.
typedef 16 NTiles;
typedef  4 NReadPorts;

interface PatReadPortIfc;
    method Action readPattern(Bit#(16) ruleId);
    method ActionValue#(Bit#(512)) readResp;
endinterface

interface ExactPatternTableIfc;
    method Action writePattern(Bit#(16) ruleId, Bit#(512) data);
    interface Vector#(NReadPorts, PatReadPortIfc) rd;
endinterface

(* synthesize *)
module mkExactPatternTable(ExactPatternTableIfc);
    Vector#(NTiles, BRAM_DUAL_PORT#(Bit#(12), Bit#(512))) mem
        <- replicateM(mkBRAMCore2(4096, True));

    Vector#(NReadPorts, FIFOF#(Bit#(2)))   pend1 <- replicateM(mkPipelineFIFOF);
    Vector#(NReadPorts, FIFOF#(Bit#(2)))   pend2 <- replicateM(mkPipelineFIFOF);
    Vector#(NReadPorts, FIFOF#(Bit#(512))) outQ  <- replicateM(mkSizedFIFOF(4));

    for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1) begin
        rule advance;
            pend2[g].enq(pend1[g].first); pend1[g].deq;
        endrule
        rule capture;
            Bit#(2) hi   = pend2[g].first; pend2[g].deq;
            Bit#(2) gb   = fromInteger(g);
            Bit#(4) tile = {hi, gb};
            outQ[g].enq(mem[tile].b.read);
        endrule
    end

    Vector#(NReadPorts, PatReadPortIfc) rdPorts = newVector;
    for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1) begin
        rdPorts[g] =
            interface PatReadPortIfc;
                method Action readPattern(Bit#(16) ruleId);
                    Bit#(2)  hi   = ruleId[3:2];
                    Bit#(2)  gb   = fromInteger(g);
                    Bit#(4)  tile = {hi, gb};
                    Bit#(12) addr = ruleId[15:4];
                    mem[tile].b.put(False, addr, ?);
                    pend1[g].enq(hi);
                endmethod
                method ActionValue#(Bit#(512)) readResp;
                    let v = outQ[g].first; outQ[g].deq; return v;
                endmethod
            endinterface;
    end

    method Action writePattern(Bit#(16) ruleId, Bit#(512) data);
        Bit#(4)  tile = ruleId[3:0];
        Bit#(12) addr = ruleId[15:4];
        mem[tile].a.put(True, addr, data);
    endmethod

    interface rd = rdPorts;
endmodule

endpackage
