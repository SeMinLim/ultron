package GramMatcher;

// gram -> Ruleid, pre, post, len

import FIFO::*;
import FIFOF::*;
import GramIdTable::*;

typedef struct {
    Bit#(16) ruleId;
    Bit#(32) anchor;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
} VerifyReq deriving (Bits, Eq, FShow);

interface GramMatcherIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Bool notBusy;
    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor);
    method ActionValue#(Maybe#(VerifyReq)) lookupResp;
    method Bool idle;
endinterface

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    GramIdTableIfc tbl      <- mkGramIdTable;
    FIFOF#(Bit#(32)) anchorQ <- mkSizedFIFOF(128);

    method Action insert(Bit#(32) gram, RuleInfo info) = tbl.insert(gram, info);
    method ActionValue#(Bool) insertAck = tbl.insertAck;
    method Bool notBusy = tbl.notBusy;

    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor);
        tbl.lookupReq(gram);
        anchorQ.enq(anchor);
    endmethod

    method ActionValue#(Maybe#(VerifyReq)) lookupResp;
        let r <- tbl.lookupResp;
        let anchor = anchorQ.first; anchorQ.deq;
        case (r) matches
            tagged Valid .info: return tagged Valid VerifyReq {
                ruleId: info.ruleId, anchor: anchor,
                pre:    info.pre,    post:   info.post,
                len:    info.len };
            tagged Invalid: return tagged Invalid;
        endcase
    endmethod

    method Bool idle = tbl.notBusy && !anchorQ.notEmpty;
endmodule

endpackage
