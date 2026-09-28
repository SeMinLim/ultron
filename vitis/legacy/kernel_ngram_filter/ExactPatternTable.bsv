package ExactPatternTable;

import BRAM::*;

interface ExactPatternTableIfc;
    method Action writePattern(Bit#(14) ruleId, Bit#(512) data);
    method Action readPattern(Bit#(14) ruleId);
    method ActionValue#(Bit#(512)) readResp;
endinterface

(* synthesize *)
module mkExactPatternTable(ExactPatternTableIfc);
    BRAM_Configure cfg = defaultValue;
    cfg.memorySize = 16384;
    cfg.latency    = 2;

    BRAM2Port#(Bit#(14), Bit#(512)) tbl <- mkBRAM2Server(cfg);

    method Action writePattern(Bit#(14) ruleId, Bit#(512) data);
        tbl.portB.request.put(BRAMRequest {
            write: True,
            responseOnWrite: False,
            address: ruleId,
            datain: data
        });
    endmethod

    method Action readPattern(Bit#(14) ruleId);
        tbl.portA.request.put(BRAMRequest {
            write: False,
            responseOnWrite: False,
            address: ruleId,
            datain: ?
        });
    endmethod

    method ActionValue#(Bit#(512)) readResp;
        let line <- tbl.portA.response.get;
        return line;
    endmethod
endmodule

endpackage
