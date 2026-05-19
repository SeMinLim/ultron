package ExactPatternTable;

import BRAMCore::*;
import FIFOF::*;
import SpecialFIFOs::*;
import Vector::*;

// 64K x 512b pattern store split into 16 URAM-friendly 4K tiles.
typedef 16 NTiles;

interface ExactPatternTableIfc;
    method Action writePattern(Bit#(16) ruleId, Bit#(512) data);
    method Action readPattern(Bit#(16) ruleId);
    method ActionValue#(Bit#(512)) readResp;
endinterface

(* synthesize *)
module mkExactPatternTable(ExactPatternTableIfc);
    Vector#(NTiles, BRAM_DUAL_PORT#(Bit#(12), Bit#(512))) mem
        <- replicateM(mkBRAMCore2(4096, True));

    FIFOF#(Bit#(4))   pendTile1 <- mkPipelineFIFOF;
    FIFOF#(Bit#(4))   pendTile2 <- mkPipelineFIFOF;
    FIFOF#(Bit#(512)) outQ      <- mkSizedFIFOF(4);

    rule advance;
        let t = pendTile1.first; pendTile1.deq;
        pendTile2.enq(t);
    endrule

    rule capture;
        let t = pendTile2.first; pendTile2.deq;
        outQ.enq(mem[t].b.read);
    endrule

    method Action writePattern(Bit#(16) ruleId, Bit#(512) data);
        Bit#(4)  tile = ruleId[15:12];
        Bit#(12) addr = ruleId[11:0];
        mem[tile].a.put(True, addr, data);
    endmethod

    method Action readPattern(Bit#(16) ruleId);
        Bit#(4)  tile = ruleId[15:12];
        Bit#(12) addr = ruleId[11:0];
        mem[tile].b.put(False, addr, ?);
        pendTile1.enq(tile);
    endmethod

    method ActionValue#(Bit#(512)) readResp;
        let v = outQ.first; outQ.deq; return v;
    endmethod
endmodule

endpackage
