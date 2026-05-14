

package BitmapBram;

import BRAM::*;
import FIFOF::*;
import Vector::*;

typedef 64 NLanes;

interface BitmapBramIfc;
    method Action writeWord(Bit#(9) lineAddr, Bit#(512) data);
    method Action lookup(Vector#(NLanes, Bit#(18)) keys);
    method ActionValue#(Vector#(NLanes, Bool)) result;
    method Bool idle;
endinterface

module mkBitmapBram(BitmapBramIfc);
    BRAM_Configure cfg = defaultValue;
    cfg.memorySize = 512;
    cfg.latency    = 1;

    Vector#(NLanes, BRAM2Port#(Bit#(9), Bit#(512))) mem <- replicateM(mkBRAM2Server(cfg));

    FIFOF#(Vector#(NLanes, Bit#(9))) keyQ   <- mkSizedFIFOF(4);
    FIFOF#(Vector#(NLanes, Bool))    resultQ <- mkSizedFIFOF(4);

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

    method Action writeWord(Bit#(9) lineAddr, Bit#(512) data);
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1)
            mem[i].portA.request.put(BRAMRequest { write: True, responseOnWrite: False,
                address: lineAddr, datain: data });
    endmethod

    // 18-bit key layout: [17:9] = BRAM line address (512 lines × 512 bits), [8:0] = bit index within line.
    method Action lookup(Vector#(NLanes, Bit#(18)) keys) if (keyQ.notFull);
        Vector#(NLanes, Bit#(9)) bitIdxs = newVector;
        for (Integer i = 0; i < valueOf(NLanes); i = i + 1) begin
            Bit#(9) lineAddr = keys[i][17:9];
            Bit#(9) bitIdx   = keys[i][8:0];
            mem[i].portB.request.put(BRAMRequest { write: False, responseOnWrite: False,
                address: lineAddr, datain: ? });
            bitIdxs[i] = bitIdx;
        end
        keyQ.enq(bitIdxs);
    endmethod

    method ActionValue#(Vector#(NLanes, Bool)) result;
        let v = resultQ.first; resultQ.deq; return v;
    endmethod

    method Bool idle = !keyQ.notEmpty && !resultQ.notEmpty;
endmodule

endpackage : BitmapBram
