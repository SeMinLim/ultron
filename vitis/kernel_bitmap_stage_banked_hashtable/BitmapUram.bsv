package BitmapUram;

import BRAM::*;
import FIFOF::*;
import Vector::*;

typedef 64 NLanes;

interface BitmapUramIfc;
    method Action writeWord(Bit#(9) lineAddr, Bit#(512) data);
    method Action lookup(Vector#(NLanes, Bit#(18)) keys);
    method ActionValue#(Vector#(NLanes, Bool)) result;
    method Bool idle;
endinterface

(* synthesize *)
module mkBitmapUram(BitmapUramIfc);
    BRAM_Configure cfg = defaultValue;
    cfg.memorySize = 4096;
    cfg.latency    = 1;

    Vector#(NLanes, BRAM2Port#(Bit#(12), Bit#(64))) mem <- replicateM(mkBRAM2Server(cfg));

    FIFOF#(Vector#(NLanes, Bit#(6))) keyQ    <- mkSizedFIFOF(4);
    FIFOF#(Vector#(NLanes, Bool))    resultQ <- mkSizedFIFOF(4);

    Reg#(Bit#(4))      wrCnt   <- mkReg(0);
    Reg#(Bit#(9))      wrLine  <- mkRegU;
    Reg#(Bit#(512))    wrData  <- mkRegU;

    rule unspoolWrites(wrCnt != 0);
        Vector#(8, Bit#(64)) chunks = unpack(wrData);
        Bit#(3)  k     = truncate(wrCnt);
        Bit#(12) addr  = {wrLine, k};
        Bit#(64) chunk = chunks[k];
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1)
            mem[i].portA.request.put(BRAMRequest { write: True, responseOnWrite: False,
                address: addr, datain: chunk });
        wrCnt <= (wrCnt == 7) ? 0 : wrCnt + 1;
    endrule

    rule collectResults(keyQ.notEmpty);
        let bitIdxs = keyQ.first; keyQ.deq;
        Vector#(NLanes, Bool) hits = newVector;
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1) begin
            let line <- mem[i].portB.response.get;
            Bit#(1) hitBit = truncate(line >> bitIdxs[i]);
            hits[i] = (hitBit != 0);
        end
        resultQ.enq(hits);
    endrule

    method Action writeWord(Bit#(9) lineAddr, Bit#(512) data) if (wrCnt == 0);
        Vector#(8, Bit#(64)) chunks = unpack(data);
        Bit#(12) addr0 = {lineAddr, 3'd0};
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1)
            mem[i].portA.request.put(BRAMRequest { write: True, responseOnWrite: False,
                address: addr0, datain: chunks[0] });
        wrLine <= lineAddr;
        wrData <= data;
        wrCnt  <= 1;
    endmethod

    method Action lookup(Vector#(NLanes, Bit#(18)) keys) if (keyQ.notFull);
        Vector#(NLanes, Bit#(6)) bitIdxs = newVector;
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1) begin
            Bit#(12) lineAddr = keys[i][17:6];
            Bit#(6)  bitIdx   = keys[i][5:0];
            mem[i].portB.request.put(BRAMRequest { write: False, responseOnWrite: False,
                address: lineAddr, datain: ? });
            bitIdxs[i] = bitIdx;
        end
        keyQ.enq(bitIdxs);
    endmethod

    method ActionValue#(Vector#(NLanes, Bool)) result;
        let v = resultQ.first; resultQ.deq; return v;
    endmethod

    method Bool idle = (wrCnt == 0) && !keyQ.notEmpty && !resultQ.notEmpty;
endmodule

endpackage
