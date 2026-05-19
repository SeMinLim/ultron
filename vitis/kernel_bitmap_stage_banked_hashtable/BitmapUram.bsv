package BitmapUram;

import BRAMCore::*;
import FIFOF::*;
import SpecialFIFOs::*;
import Vector::*;

typedef 64 NLanes;

// 64-lane 18-bit bitmap; lookup splits key[17:6] line, key[5:0] bit.
interface BitmapUramIfc;
    method Action writeWord(Bit#(9) lineAddr, Bit#(512) data);
    method Action lookup(Vector#(NLanes, Bit#(18)) keys);
    method ActionValue#(Vector#(NLanes, Bool)) result;
    method Bool idle;
endinterface

(* synthesize *)
module mkBitmapUram(BitmapUramIfc);
    Vector#(NLanes, BRAM_DUAL_PORT#(Bit#(12), Bit#(64))) mem
        <- replicateM(mkBRAMCore2(4096, False));

    FIFOF#(Vector#(NLanes, Bit#(6))) pipeQ <- mkPipelineFIFOF;

    FIFOF#(Vector#(NLanes, Bool)) resultQ <- mkSizedFIFOF(4);

    Reg#(Bit#(4))   wrCnt  <- mkReg(0);
    Reg#(Bit#(9))   wrLine <- mkRegU;
    Reg#(Bit#(512)) wrData <- mkRegU;

    rule unspoolWrites(wrCnt != 0);
        Vector#(8, Bit#(64)) chunks = unpack(wrData);
        Bit#(3)  k     = truncate(wrCnt);
        Bit#(12) addr  = {wrLine, k};
        Bit#(64) chunk = chunks[k];
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1)
            mem[i].a.put(True, addr, chunk);
        wrCnt <= (wrCnt == 7) ? 0 : wrCnt + 1;
    endrule

    rule capture(pipeQ.notEmpty && resultQ.notFull);
        let bitIdxs = pipeQ.first; pipeQ.deq;
        Vector#(NLanes, Bool) hits = newVector;
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1) begin
            Bit#(64) line = mem[i].b.read;
            Bit#(1) hitBit = truncate(line >> bitIdxs[i]);
            hits[i] = (hitBit != 0);
        end
        resultQ.enq(hits);
    endrule

    method Action writeWord(Bit#(9) lineAddr, Bit#(512) data) if (wrCnt == 0);
        Vector#(8, Bit#(64)) chunks = unpack(data);
        Bit#(12) addr0 = {lineAddr, 3'd0};
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1)
            mem[i].a.put(True, addr0, chunks[0]);
        wrLine <= lineAddr;
        wrData <= data;
        wrCnt  <= 1;
    endmethod

    method Action lookup(Vector#(NLanes, Bit#(18)) keys);
        Vector#(NLanes, Bit#(6)) bitIdxs = newVector;
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1) begin
            Bit#(12) lineAddr = keys[i][17:6];
            Bit#(6)  bitIdx   = keys[i][5:0];
            mem[i].b.put(False, lineAddr, ?);
            bitIdxs[i] = bitIdx;
        end
        pipeQ.enq(bitIdxs);
    endmethod

    method ActionValue#(Vector#(NLanes, Bool)) result;
        let v = resultQ.first; resultQ.deq; return v;
    endmethod

    method Bool idle = (wrCnt == 0) && !pipeQ.notEmpty && !resultQ.notEmpty;
endmodule

endpackage
