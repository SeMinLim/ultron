package GramMatcher;

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
    Bit#(6)  pay_off;
} GramCtx deriving (Bits);

// Valid = hit to forward, Invalid = end-of-gram sentinel
typedef struct {
    Maybe#(VerifyReq) vreq;
    Bit#(32)          payLen;
    Bit#(1)           epoch;
    Bit#(6)           pay_off;
} GramResult deriving (Bits);

interface GramMatcherIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(1) epoch, Bit#(6) pay_off);
    method ActionValue#(GramResult) lookupResp;
    method Bool idle;
endinterface

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    GramIdTableIfc  tbl  <- mkGramIdTable;
    FIFOF#(GramCtx) ctxQ <- mkSizedFIFOF(512);
    FIFOF#(GramResult) outQ <- mkSizedFIFOF(512);

    // Only forward hits to outQ; sentinel silently advances ctxQ.
    // Filtering sentinels here means KernelMain sees only valid hits —
    // no need for sentinel-drain rules or gramStageQ.
    rule forwardResult (ctxQ.notEmpty);
        let r <- tbl.getResult;
        let ctx = ctxQ.first;
        case (r) matches
            tagged Valid .info: begin
                outQ.enq(GramResult {
                    vreq: tagged Valid VerifyReq {
                        ruleId: info.ruleId, anchor: ctx.anchor,
                        pre:    info.pre,    post:   info.post,
                        len:    info.len },
                    payLen:  ctx.payLen,
                    epoch:   ctx.epoch,
                    pay_off: ctx.pay_off });
            end
            tagged Invalid: begin
                ctxQ.deq;  // advance context, emit nothing
            end
        endcase
    endrule

    method Action insert(Bit#(32) gram, RuleInfo info) = tbl.insert(gram, info);
    method ActionValue#(Bool) insertAck = tbl.insertAck;

    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(1) epoch, Bit#(6) pay_off);
        tbl.lookupReq(gram);
        ctxQ.enq(GramCtx { anchor: anchor, payLen: payLen,
                            epoch: epoch, pay_off: pay_off });
    endmethod

    method ActionValue#(GramResult) lookupResp;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method Bool idle = tbl.notBusy && !ctxQ.notEmpty && !outQ.notEmpty;
endmodule

endpackage
