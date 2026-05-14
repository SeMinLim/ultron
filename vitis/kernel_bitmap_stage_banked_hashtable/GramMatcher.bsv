package GramMatcher;

import CuckooHash::*;
import FIFO::*;
import FIFOF::*;
import Vector::*;

typedef 64 NHtBanks;

typedef 12 SubKeyBits;

typedef struct {
    Bit#(16) ruleId;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
    Bool     stage2;
    Bit#(18) nextGramKey;
    Bit#(5)  pad;          // pads RuleInfo to exactly 64 bits = CuckooHash valSz
} RuleInfo deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(16) ruleId;
    Bit#(32) anchor;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
    Bool     stage2;
    Bit#(18) nextGramKey;
} VerifyReq deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) anchor;
    Bit#(32) payLen;
    Bit#(1)  epoch;
    Bit#(6)  pay_off;
    Bool     viable2;
} GramCtx deriving (Bits);

typedef struct {
    VerifyReq vreq;
    Bit#(32)  payLen;
    Bit#(1)   epoch;
    Bit#(6)   pay_off;
    Bool      viable2;
} GramResult deriving (Bits);

interface GramMatcherIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(1) epoch, Bit#(6) pay_off,
                            Bool viable2);
    method ActionValue#(GramResult) lookupResp;
    method Bool idle;
endinterface

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    Vector#(NHtBanks, CuckooHashIfc#(SubKeyBits, 64, 5)) banks
        <- replicateM(mkCuckooHash);

    // pendBankQ records which bank each lookup was sent to, preserving issue order for responses.
    FIFOF#(Bit#(6))    pendBankQ <- mkSizedFIFOF(64);
    FIFOF#(GramCtx)    ctxQ      <- mkSizedFIFOF(64);
    FIFOF#(GramResult) outQ      <- mkSizedFIFOF(64);

    FIFOF#(Bit#(6)) pendInsertBankQ <- mkSizedFIFOF(8);
    FIFOF#(Bool)    ackQ            <- mkSizedFIFOF(8);

    function Bit#(18) mix18(Bit#(18) k);
        Bit#(18) x = k ^ (k >> 6);
        x = x ^ (x >> 7);
        x = x ^ (x << 11);
        return x;
    endfunction
    // 18-bit gram key after mixing: low 6 bits → bank selector, high 12 bits → per-bank subkey.
    function Bit#(6) bankOf(Bit#(32) key)            = mix18(key[17:0])[5:0];
    function Bit#(SubKeyBits) subKeyOf(Bit#(32) key) = mix18(key[17:0])[17:6];

    rule forwardResult (pendBankQ.notEmpty && ctxQ.notEmpty);
        let bank = pendBankQ.first;
        let v <- banks[bank].lookupResp;
        pendBankQ.deq;
        let ctx = ctxQ.first; ctxQ.deq;
        case (v) matches
            tagged Valid .b: begin
                RuleInfo info = unpack(b);
                outQ.enq(GramResult {
                    vreq: VerifyReq {
                        ruleId:      info.ruleId, anchor:      ctx.anchor,
                        pre:         info.pre,    post:        info.post,
                        len:         info.len,
                        stage2:      info.stage2,
                        nextGramKey: info.nextGramKey },
                    payLen:  ctx.payLen,
                    epoch:   ctx.epoch,
                    pay_off: ctx.pay_off,
                    viable2: ctx.viable2 });
            end
            tagged Invalid: noAction;
        endcase
    endrule

    rule forwardInsertAck (pendInsertBankQ.notEmpty);
        let bank = pendInsertBankQ.first; pendInsertBankQ.deq;
        let ok <- banks[bank].insertAck;
        ackQ.enq(ok);
    endrule

    method Action insert(Bit#(32) gram, RuleInfo info);
        let bank = bankOf(gram);
        banks[bank].insert(zeroExtend(subKeyOf(gram)), pack(info));
        pendInsertBankQ.enq(bank);
    endmethod

    method ActionValue#(Bool) insertAck;
        let v = ackQ.first; ackQ.deq; return v;
    endmethod

    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(1) epoch, Bit#(6) pay_off,
                            Bool viable2);
        let bank = bankOf(gram);
        banks[bank].lookupReq(zeroExtend(subKeyOf(gram)));
        pendBankQ.enq(bank);
        ctxQ.enq(GramCtx { anchor: anchor, payLen: payLen,
                            epoch: epoch, pay_off: pay_off,
                            viable2: viable2 });
    endmethod

    method ActionValue#(GramResult) lookupResp;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method Bool idle;
        Bool allBanksIdle = True;
        for (Integer i = 0; i < valueOf(NHtBanks); i = i + 1)
            allBanksIdle = allBanksIdle && banks[i].notBusy;
        return allBanksIdle && !ctxQ.notEmpty && !outQ.notEmpty
                            && !pendBankQ.notEmpty && !pendInsertBankQ.notEmpty;
    endmethod
endmodule

endpackage
