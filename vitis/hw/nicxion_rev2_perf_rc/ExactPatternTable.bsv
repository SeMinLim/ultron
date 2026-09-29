package ExactPatternTable;

import BRAMCore::*;
import FIFOF::*;
import SpecialFIFOs::*;
import Vector::*;

typedef 16 NTiles;
typedef  4 NReadPorts;
typedef TLog#(NReadPorts)                  PortBits;   // tile index low bits = port
typedef TLog#(TDiv#(NTiles, NReadPorts))   HiBits;     // tile index high bits = tile within port

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
    Vector#(NTiles, BRAM_DUAL_PORT#(Bit#(9), Bit#(512))) mem
        <- replicateM(mkBRAMCore2(512, True));

    function Vector#(TDiv#(NTiles, NReadPorts), BRAM_DUAL_PORT#(Bit#(9), Bit#(512))) portTiles(Integer g);
        function BRAM_DUAL_PORT#(Bit#(9), Bit#(512)) tileOf(Integer hi) = mem[hi * valueOf(NReadPorts) + g];
        return genWith(tileOf);
    endfunction
    Vector#(NReadPorts, Vector#(TDiv#(NTiles, NReadPorts), BRAM_DUAL_PORT#(Bit#(9), Bit#(512))))
        own = genWith(portTiles);

    Vector#(NReadPorts, FIFOF#(Bit#(HiBits))) pend1 <- replicateM(mkPipelineFIFOF);
    Vector#(NReadPorts, FIFOF#(Bit#(HiBits))) pend2 <- replicateM(mkPipelineFIFOF);
    Vector#(NReadPorts, FIFOF#(Bit#(512))) outQ  <- replicateM(mkSizedFIFOF(4));

    for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1) begin
        rule advance;
            pend2[g].enq(pend1[g].first); pend1[g].deq;
        endrule
        rule capture;
            Bit#(HiBits) hi = pend2[g].first; pend2[g].deq;
            outQ[g].enq(own[g][hi].b.read);
        endrule
    end

    RWire#(Tuple3#(Bit#(4), Bit#(9), Bit#(512))) wrW <- mkRWire;
    Reg#(Bool)      wrV    <- mkReg(False);
    Reg#(Bit#(4))   wrTile <- mkRegU;
    Reg#(Bit#(9))   wrAddr <- mkRegU;
    Reg#(Bit#(512)) wrData <- mkRegU;

    (* fire_when_enabled, no_implicit_conditions *)
    rule latchWrite;
        wrV <= isValid(wrW.wget);
        if (wrW.wget matches tagged Valid {.t, .a, .d}) begin
            wrTile <= t; wrAddr <= a; wrData <= d;
        end
    endrule

    rule doWrite (wrV);
        mem[wrTile].a.put(True, wrAddr, wrData);
    endrule

    Vector#(NReadPorts, PatReadPortIfc) rdPorts = newVector;
    for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1) begin
        rdPorts[g] =
            interface PatReadPortIfc;
                method Action readPattern(Bit#(16) ruleId);
                    Bit#(4)      tile = ruleId[3:0];
                    Bit#(HiBits) hi   = truncate(tile >> valueOf(PortBits));
                    Bit#(9) addr = ruleId[12:4];
                    own[g][hi].b.put(False, addr, ?);
                    pend1[g].enq(hi);
                endmethod
                method ActionValue#(Bit#(512)) readResp;
                    let v = outQ[g].first; outQ[g].deq; return v;
                endmethod
            endinterface;
    end

    method Action writePattern(Bit#(16) ruleId, Bit#(512) data);
        wrW.wset(tuple3(ruleId[3:0], ruleId[12:4], data));
    endmethod

    interface rd = rdPorts;
endmodule

endpackage
