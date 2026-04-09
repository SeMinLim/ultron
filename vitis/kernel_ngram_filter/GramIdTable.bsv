package GramIdTable;

import CuckooHash::*;
import FIFOF::*;
import Vector::*;

typedef struct {
    Bit#(16) ruleId;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
} RuleInfo deriving (Bits, Eq, FShow);

interface GramIdTableIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Bool notBusy;
    method Action lookupReq(Bit#(32) gram);
    method ActionValue#(Maybe#(RuleInfo)) lookupResp;
endinterface

typedef enum { LkIdle, LkReq, LkRsp } LkState deriving (Bits, Eq, FShow);

(* synthesize *)
module mkGramIdTable(GramIdTableIfc);

    Vector#(16, CuckooHashIfc#(32, 40, 9)) ht <- replicateM(mkCuckooHash);

    // insert
    Reg#(Bit#(4))  insertTbl <- mkReg(0);
    FIFOF#(Bool)   ackOutQ   <- mkSizedFIFOF(4);
    FIFOF#(Bool)   htAckQ    <- mkSizedFIFOF(4);

    for (Integer i = 0; i < 16; i = i + 1) begin
        rule getInsAck;
            let ok <- ht[i].insertAck;
            htAckQ.enq(ok);
        endrule
    end

    rule processAck (htAckQ.notEmpty);
        let ok = htAckQ.first; htAckQ.deq;
        ackOutQ.enq(True);
    endrule

    // lookup
    FIFOF#(Bit#(32))          inQ  <- mkSizedFIFOF(128);
    FIFOF#(Maybe#(Bit#(40))) outQ  <- mkSizedFIFOF(128);

    Vector#(16, Reg#(Maybe#(Maybe#(Bit#(40))))) rspStage
        <- replicateM(mkReg(tagged Invalid));

    for (Integer i = 0; i < 16; i = i + 1) begin
        rule drainStage (rspStage[i] == tagged Invalid);
            let v <- ht[i].lookupResp;
            rspStage[i] <= tagged Valid v;
        endrule
    end

    Reg#(LkState)  lkSt       <- mkReg(LkIdle);
    Reg#(Bit#(32)) lkGram     <- mkReg(0);
    Reg#(Bit#(4))  lkStartTbl <- mkReg(0);
    Reg#(Bit#(4))  lkCurTbl   <- mkReg(0);
    Reg#(Bit#(4))  lkTried    <- mkReg(0);

    rule doLkIdle (lkSt == LkIdle && inQ.notEmpty);
        let gram = inQ.first; inQ.deq;
        lkGram   <= gram;
        lkCurTbl <= lkStartTbl;
        lkTried  <= 0;
        lkSt     <= LkReq;
    endrule

    rule doLkReq (lkSt == LkReq);
        for (Integer i = 0; i < 16; i = i + 1)
            if (lkCurTbl == fromInteger(i))
                ht[i].lookupReq(lkGram);
        lkSt <= LkRsp;
    endrule

    rule doLkRsp (lkSt == LkRsp);
        let staged = (readVReg(rspStage))[lkCurTbl];
        case (staged) matches
            tagged Invalid: noAction;
            tagged Valid .r: begin
                for (Integer i = 0; i < 16; i = i + 1)
                    if (lkCurTbl == fromInteger(i))
                        rspStage[i] <= tagged Invalid;
                if (isValid(r)) begin
                    outQ.enq(tagged Valid validValue(r));
                    lkStartTbl <= lkStartTbl + 1;
                    lkSt <= LkIdle;
                end else if (lkTried == 15) begin
                    outQ.enq(tagged Invalid);
                    lkStartTbl <= lkStartTbl + 1;
                    lkSt <= LkIdle;
                end else begin
                    lkCurTbl <= lkCurTbl + 1;
                    lkTried  <= lkTried + 1;
                    lkSt <= LkReq;
                end
            end
        endcase
    endrule

    method Action insert(Bit#(32) gram, RuleInfo info);
        for (Integer i = 0; i < 16; i = i + 1)
            if (insertTbl == fromInteger(i))
                ht[i].insert(gram, pack(info));
        insertTbl <= insertTbl + 1;
    endmethod

    method ActionValue#(Bool) insertAck;
        let r = ackOutQ.first; ackOutQ.deq;
        return r;
    endmethod

    method Bool notBusy;
        Bool allIdle = True;
        for (Integer i = 0; i < 16; i = i + 1)
            allIdle = allIdle && ht[i].notBusy;
        return allIdle;
    endmethod

    method Action lookupReq(Bit#(32) gram);
        inQ.enq(gram);
    endmethod

    method ActionValue#(Maybe#(RuleInfo)) lookupResp;
        let r = outQ.first; outQ.deq;
        case (r) matches
            tagged Valid .v: return tagged Valid unpack(v);
            tagged Invalid:  return tagged Invalid;
        endcase
    endmethod

endmodule

endpackage
