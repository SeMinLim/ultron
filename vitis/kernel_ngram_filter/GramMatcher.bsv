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

typedef struct {
    Bit#(32) anchor;
    Bit#(32) payLen;
    Bit#(1)  epoch;
} GramCtx deriving (Bits);

interface GramMatcherIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Bool notBusy;
    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor, Bit#(32) payLen, Bit#(1) epoch);
    method ActionValue#(Tuple3#(Maybe#(VerifyReq), Bit#(32), Bit#(1))) lookupResp;
    method Bool idle;
endinterface

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    GramIdTableIfc             tbl  <- mkGramIdTable;
    FIFOF#(GramCtx)            ctxQ <- mkSizedFIFOF(128);

    method Action insert(Bit#(32) gram, RuleInfo info) = tbl.insert(gram, info);
    method ActionValue#(Bool) insertAck = tbl.insertAck;
    method Bool notBusy = tbl.notBusy;

    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor, Bit#(32) payLen, Bit#(1) epoch);
        tbl.lookupReq(gram);
        ctxQ.enq(GramCtx { anchor: anchor, payLen: payLen, epoch: epoch });
    endmethod

    method ActionValue#(Tuple3#(Maybe#(VerifyReq), Bit#(32), Bit#(1))) lookupResp;
        let r   <- tbl.lookupResp;
        let ctx = ctxQ.first; ctxQ.deq;
        case (r) matches
            tagged Valid .info:
                return tuple3(tagged Valid VerifyReq {
                    ruleId: info.ruleId, anchor: ctx.anchor,
                    pre:    info.pre,    post:   info.post,
                    len:    info.len }, ctx.payLen, ctx.epoch);
            tagged Invalid:
                return tuple3(tagged Invalid, ctx.payLen, ctx.epoch);
        endcase
    endmethod

    method Bool idle = tbl.notBusy && !ctxQ.notEmpty;
endmodule

endpackage
