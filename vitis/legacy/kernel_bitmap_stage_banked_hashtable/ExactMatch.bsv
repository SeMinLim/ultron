package ExactMatch;

import FIFOF::*;
import BRAM::*;
import Vector::*;
import GramMatcher::*;
import ExactPatternTable::*;

typedef struct {
    Bool     hit;
    Bit#(16) ruleId;
    Bit#(32) matchPos;
    Bit#(32) payLen;
    Bit#(3)  epoch;
} ExMatchResult deriving (Bits, Eq, FShow);

typedef struct {
    VerifyReq req;
    Bit#(32)  payload_len;
    Bit#(3)   epoch;
    Bit#(6)   pay_off;
} ExactRequest deriving (Bits, Eq, FShow);

typedef enum {
    EXReady,
    EXPatRsp,
    EXCmpReq,
    EXCmpRsp
} EXState deriving (Bits, Eq, FShow);

function Bit#(8) foldCase(Bit#(8) b);
    return ((b >= 8'h41) && (b <= 8'h5A)) ? (b | 8'h20) : b;
endfunction

interface ExactMatchIfc;
    method Action putPayloadWord(Bit#(512) word, Bool last, Bit#(3) epoch);

    method Action putRequest(VerifyReq r, Bit#(32) payload_len,
                             Bit#(3) epoch, Bit#(6) pay_off);

    method ActionValue#(ExMatchResult) getResult;
    method Bool notEmpty;
    method Bool inputPending;
    method Bool canAcceptRequest;
endinterface

module mkExactMatch#(PatReadPortIfc patPort)(ExactMatchIfc);
    Integer linesPerEpoch = 256;
    Integer payloadLines = 2048;

    BRAM_Configure cfgPayload = defaultValue;
    cfgPayload.memorySize = payloadLines;
    cfgPayload.latency    = 1;

    // Eight 16KB epoch slots. Port A writes packet payload; port B verifies.
    BRAM2Port#(Bit#(11), Bit#(512)) payloadTbl <- mkBRAM2Server(cfgPayload);

    FIFOF#(ExactRequest)  inQ  <- mkSizedFIFOF(64);
    FIFOF#(ExMatchResult) outQ <- mkSizedFIFOF(64);

    Reg#(EXState)      st         <- mkReg(EXReady);
    Reg#(Bit#(8))      payWrLine  <- mkReg(0);
    Reg#(ExactRequest) curReq     <- mkRegU;
    Reg#(Int#(32))     curStart   <- mkReg(0);
    Reg#(Bit#(32))     cmpPos     <- mkReg(0);
    Reg#(Bit#(6))      cmpByteOff <- mkReg(0);
    Reg#(Bit#(512))    patReg     <- mkRegU;

    rule doReady (st == EXReady && inQ.notEmpty);
        let r = inQ.first; inQ.deq;

        Int#(32) startI  = unpack(r.req.anchor) + signExtend(r.req.pre);
        Int#(32) endI    = unpack(r.req.anchor) + 3 + signExtend(r.req.post);
        Int#(32) patLenI = unpack(zeroExtend(r.req.len));
        Int#(32) payLenI = unpack(r.payload_len);
        Bool anchorMismatch = (r.req.anchorGram != r.req.pktAnchorGram);
        Bool nextGramMismatch = r.req.stage2 &&
                                (r.req.nextGramKey != r.req.pktNextGramKey);

        Bool bad = (r.req.len == 0 || startI < 0 || endI < 0 ||
                    startI > endI  || endI > payLenI ||
                    (endI - startI) != patLenI ||
                    anchorMismatch || nextGramMismatch);
        if (bad) begin
            outQ.enq(ExMatchResult { hit: False, ruleId: 0,
                                     matchPos: 0, payLen: r.payload_len,
                                     epoch: r.epoch });
        end else begin
            patPort.readPattern(r.req.ruleId);
            curReq   <= r;
            curStart <= startI;
            st       <= EXPatRsp;
        end
    endrule

    rule doPatRsp (st == EXPatRsp);
        let line <- patPort.readResp;
        patReg <= line;
        cmpPos <= 0;
        st     <= EXCmpReq;
    endrule

    function Bit#(8) anchorIndex(VerifyReq req);
        Int#(8) idx = -req.pre;
        return pack(idx);
    endfunction

    function Bool isAnchorByte(Bit#(32) pos, VerifyReq req);
        Bit#(8) a8 = anchorIndex(req);
        Bit#(32) a = zeroExtend(a8);
        return (a + 3 <= zeroExtend(req.len)) && (pos >= a) && (pos < a + 3);
    endfunction

    rule doCmpReq (st == EXCmpReq);
        Int#(32) payPosI    = curStart + unpack(cmpPos);
        Bit#(32) bramByte32 = pack(payPosI) + zeroExtend(curReq.pay_off);
        Bit#(8)  lineAddr   = truncate(bramByte32 >> 6);
        Bit#(6)  byteOff    = truncate(bramByte32);
        Bit#(9)  lastOff    = zeroExtend(byteOff) + zeroExtend(curReq.req.len);
        Bool     oneLineStart = (cmpPos == 0) && (lastOff <= 64);

        if (!oneLineStart && isAnchorByte(cmpPos, curReq.req)) begin
            if (cmpPos + 1 >= zeroExtend(curReq.req.len)) begin
                outQ.enq(ExMatchResult { hit: True,  ruleId: curReq.req.ruleId,
                                         matchPos: pack(curStart), payLen: curReq.payload_len,
                                         epoch: curReq.epoch });
                st <= EXReady;
            end else begin
                cmpPos <= cmpPos + 1;
            end
        end else begin
            payloadTbl.portB.request.put(BRAMRequest {
                write: False, responseOnWrite: False,
                address: {curReq.epoch, lineAddr}, datain: ? });
            cmpByteOff <= byteOff;
            st <= EXCmpRsp;
        end
    endrule

    function Bool oneLineMatch(Bit#(512) payLine, Bit#(6) startOff,
                               Bit#(8) len, Bit#(8) anchorIdx,
                               Bit#(512) patLine);
        Bool ok = True;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(7) off = zeroExtend(startOff) + fromInteger(i);
            Bit#(9) paySh = zeroExtend(off[5:0]) << 3;
            Bit#(9) patSh = fromInteger(i * 8);
            Bit#(8) payB = truncate(payLine >> paySh);
            Bit#(8) patB = truncate(patLine >> patSh);
            Bit#(8) idx = fromInteger(i);
            Bool skip = (anchorIdx + 3 <= len) &&
                        (idx >= anchorIdx) && (idx < anchorIdx + 3);
            if (idx < len && !skip && patB != foldCase(payB))
                ok = False;
        end
        return ok;
    endfunction

    // Single-line patterns use one BRAM read; cross-line patterns fall back to
    // byte-at-a-time comparison.
    rule doCmpRsp (st == EXCmpRsp);
        let payLine <- payloadTbl.portB.response.get;

        Bit#(9) lastOff = zeroExtend(cmpByteOff) + zeroExtend(curReq.req.len);
        Bool oneLine = (cmpPos == 0) && (lastOff <= 64);

        if (oneLine) begin
            Bool hit = oneLineMatch(payLine, cmpByteOff, curReq.req.len,
                                    anchorIndex(curReq.req), patReg);
            outQ.enq(ExMatchResult { hit: hit,
                                     ruleId: hit ? curReq.req.ruleId : 0,
                                     matchPos: hit ? pack(curStart) : 0,
                                     payLen: curReq.payload_len,
                                     epoch: curReq.epoch });
            st <= EXReady;
        end else begin
            Bit#(9) paySh = zeroExtend(cmpByteOff) << 3;
            Bit#(8) payB  = truncate(payLine >> paySh);

            Bit#(9) patSh = {truncate(cmpPos[5:0]), 3'b0};
            Bit#(8) patB  = truncate(patReg >> patSh);

            if (patB != foldCase(payB)) begin
                outQ.enq(ExMatchResult { hit: False, ruleId: 0,
                                         matchPos: 0, payLen: curReq.payload_len,
                                         epoch: curReq.epoch });
                st <= EXReady;
            end else if (cmpPos + 1 >= zeroExtend(curReq.req.len)) begin
                outQ.enq(ExMatchResult { hit: True,  ruleId: curReq.req.ruleId,
                                         matchPos: pack(curStart), payLen: curReq.payload_len,
                                         epoch: curReq.epoch });
                st <= EXReady;
            end else begin
                cmpPos <= cmpPos + 1;
                st     <= EXCmpReq;
            end
        end
    endrule

    method Action putPayloadWord(Bit#(512) word, Bool last, Bit#(3) epoch);
        payloadTbl.portA.request.put(BRAMRequest {
            write: True, responseOnWrite: False,
            address: {epoch, payWrLine}, datain: word });
        if (last)
            payWrLine <= 0;
        else if (payWrLine < fromInteger(linesPerEpoch - 1))
            payWrLine <= payWrLine + 1;
    endmethod

    method Action putRequest(VerifyReq r, Bit#(32) payload_len,
                             Bit#(3) epoch, Bit#(6) pay_off) if (inQ.notFull);
        inQ.enq(ExactRequest { req: r, payload_len: payload_len,
                               epoch: epoch, pay_off: pay_off });
    endmethod


    method ActionValue#(ExMatchResult) getResult;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method Bool notEmpty     = outQ.notEmpty;
    method Bool inputPending = inQ.notEmpty || (st != EXReady);
    method Bool canAcceptRequest = inQ.notFull;
endmodule

// Banked by ruleId[1:0]; each engine owns a pattern read port and payload copy.
module mkExactMatchParallel#(ExactPatternTableIfc patTbl)(ExactMatchIfc);
    ExactMatchIfc eng0 <- mkExactMatch(patTbl.rd[0]);
    ExactMatchIfc eng1 <- mkExactMatch(patTbl.rd[1]);
    ExactMatchIfc eng2 <- mkExactMatch(patTbl.rd[2]);
    ExactMatchIfc eng3 <- mkExactMatch(patTbl.rd[3]);
    Vector#(NReadPorts, ExactMatchIfc) eng =
        cons(eng0, cons(eng1, cons(eng2, cons(eng3, nil))));

    Reg#(Bit#(2)) rr <- mkReg(0);

    method Action putPayloadWord(Bit#(512) word, Bool last, Bit#(3) epoch);
        for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1)
            eng[g].putPayloadWord(word, last, epoch);
    endmethod

    method Action putRequest(VerifyReq r, Bit#(32) payload_len,
                             Bit#(3) epoch, Bit#(6) pay_off);
        eng[r.ruleId[1:0]].putRequest(r, payload_len, epoch, pay_off);
    endmethod

    method ActionValue#(ExMatchResult) getResult;
        Bit#(2) sel = eng[rr].notEmpty     ? rr     :
                      eng[rr+1].notEmpty   ? rr + 1 :
                      eng[rr+2].notEmpty   ? rr + 2 : rr + 3;
        let v <- eng[sel].getResult;
        rr <= sel + 1;
        return v;
    endmethod

    method Bool notEmpty = eng0.notEmpty || eng1.notEmpty
                        || eng2.notEmpty || eng3.notEmpty;

    method Bool inputPending = eng0.inputPending || eng1.inputPending
                            || eng2.inputPending || eng3.inputPending;

    method Bool canAcceptRequest = eng0.canAcceptRequest && eng1.canAcceptRequest
                                && eng2.canAcceptRequest && eng3.canAcceptRequest;
endmodule

endpackage
