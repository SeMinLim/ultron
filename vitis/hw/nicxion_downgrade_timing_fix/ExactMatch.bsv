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
    Bit#(32) endOff;   // pattern end offset (anchor+3+post); the end-of-payload
                       // reject is deferred to drain time where the FINAL packet
                       // length is known (length arrives only on the tlast beat).
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
    EXIssue,
    EXPatRsp,
    EXCmpReq,
    EXCmpRsp,
    EXCmpRot,
    EXCmpEq,
    EXCmpChk,
    EXEmit
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
    Integer linesPerEpoch = 64;
    Integer payloadLines = 512;

    BRAM_Configure cfgPayload = defaultValue;
    cfgPayload.memorySize = payloadLines;
    cfgPayload.latency    = 2;

    // Eight 4KB epoch slots, addressed as {epoch[2:0], line[5:0]}.
    // Port A writes packet payload; port B verifies.
    BRAM2Port#(Bit#(9), Bit#(512)) payloadTbl <- mkBRAM2Server(cfgPayload);

    FIFOF#(ExactRequest)  inQ  <- mkSizedFIFOF(64);
    FIFOF#(ExMatchResult) outQ <- mkSizedFIFOF(64);

    Reg#(EXState)      st         <- mkReg(EXReady);
    Reg#(Bit#(6))      payWrLine  <- mkReg(0);
    Reg#(ExactRequest) curReq     <- mkRegU;
    Reg#(Int#(32))     curStart   <- mkReg(0);
    Reg#(Int#(32))     curEnd     <- mkReg(0);
    Reg#(Bit#(32))     cmpPos     <- mkReg(0);
    Reg#(Bit#(6))      cmpByteOff <- mkReg(0);
    Reg#(Bit#(512))    patReg     <- mkRegU;
    Reg#(Bool)         reqBad     <- mkRegU;   // doReady verdict, acted on in doIssue
    Reg#(Bit#(512))    cmpRaw     <- mkRegU;   // case-folded line, before rotation
    Reg#(Bit#(32))     bramByte   <- mkRegU;   // curStart + pay_off + cmpPos
    Reg#(Bool)         firstPosR  <- mkRegU;   // cmpPos == 0
    Reg#(Bool)         oneLineR   <- mkRegU;   // pattern fits in the first line
    Reg#(Bool)         lastR      <- mkRegU;   // cmpPos + 1 >= len
    Reg#(Bool)         anchorR    <- mkRegU;   // cmpPos is one of the 3 anchor bytes
    Reg#(Bool)         anchorOk   <- mkRegU;   // anchor + 3 <= len
    Reg#(Bit#(9))      aLo9       <- mkRegU;   // anchor byte index
    Reg#(Bool)         eqAll      <- mkRegU;   // one-line compare verdict
    Reg#(Bool)         byte0Eq    <- mkRegU;   // byte-wise compare verdict
    Reg#(Bool)         resHit     <- mkRegU;   // result emitted by doEmit
    // Compare pipeline: doCmpRsp folds, doCmpRot rotates, doCmpEq compares,
    // doCmpChk decides, doEmit writes outQ.
    Reg#(Bit#(512))    cmpLine    <- mkRegU;
    Reg#(Bit#(64))     cmpMask    <- mkRegU;   // bytes that must match (idx < len, not anchor)
    Reg#(Bool)         cmpOneLine <- mkRegU;
    Reg#(Bit#(8))      patByte    <- mkRegU;   // pattern byte for the byte-wise path

    rule doReady (st == EXReady);
        let r = inQ.first; inQ.deq;

        Int#(32) startI  = unpack(r.req.anchor) + signExtend(r.req.pre);
        Int#(32) endI    = unpack(r.req.anchor) + 3 + signExtend(r.req.post);
        Int#(32) patLenI = unpack(zeroExtend(r.req.len));
        Bool anchorMismatch = (r.req.anchorGram != r.req.pktAnchorGram);
        Bool nextGramMismatch = r.req.stage2 &&
                                (r.req.nextGramKey != r.req.pktNextGramKey);

        Bool bad = (r.req.len == 0 || startI < 0 || endI < 0 ||
                    startI > endI  ||
                    (endI - startI) != patLenI ||
                    anchorMismatch || nextGramMismatch);
        reqBad   <= bad;
        curReq   <= r;
        curStart <= startI;
        curEnd   <= endI;
        st       <= EXIssue;
    endrule

    rule doIssue (st == EXIssue);
        if (reqBad) begin
            resHit <= False;
            st     <= EXEmit;
        end else begin
            patPort.readPattern(curReq.req.ruleId);
            st <= EXPatRsp;
        end
    endrule

    function Bit#(8) anchorIndex(VerifyReq req);
        Int#(8) idx = -req.pre;
        return pack(idx);
    endfunction

    rule doPatRsp (st == EXPatRsp);
        let line <- patPort.readResp;
        patReg <= line;
        Bit#(8)  len     = curReq.req.len;
        Bit#(8)  aIdx    = anchorIndex(curReq.req);
        Bit#(9)  len9    = zeroExtend(len);
        Bit#(9)  a9      = zeroExtend(aIdx);
        Bool     aOk     = (a9 + 3 <= len9);
        Bit#(32) bb      = pack(curStart) + zeroExtend(curReq.pay_off);
        Bit#(9)  lastOff = zeroExtend(bb[5:0]) + len9;
        Bit#(64) mask    = 0;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(8) idx  = fromInteger(i);
            Bool    skip = (aIdx + 3 <= len) && (idx >= aIdx) && (idx < aIdx + 3);
            mask[i] = pack(idx < len && !skip);
        end
        cmpMask   <= mask;
        anchorOk  <= aOk;
        aLo9      <= a9;
        cmpPos    <= 0;
        bramByte  <= bb;
        firstPosR <= True;
        oneLineR  <= (lastOff <= 64);
        lastR     <= (1 >= len9);             // cmpPos + 1 >= len at cmpPos 0
        anchorR   <= aOk && (a9 == 0);        // 0 >= a && 0 < a + 3
        st        <= EXCmpReq;
    endrule

    // Step to the next pattern byte, updating the derived position flags.
    function Action advancePos();
        action
            Bit#(9) np = truncate(cmpPos) + 1;
            cmpPos    <= cmpPos + 1;
            bramByte  <= bramByte + 1;
            firstPosR <= False;
            lastR     <= (np + 1 >= zeroExtend(curReq.req.len));
            anchorR   <= anchorOk && (np >= aLo9) && (np < aLo9 + 3);
        endaction
    endfunction

    rule doCmpReq (st == EXCmpReq);
        Bool oneLineStart = firstPosR && oneLineR;
        if (!oneLineStart && anchorR) begin
            if (lastR) begin
                resHit <= True;
                st     <= EXEmit;
            end else
                advancePos;
        end else begin
            payloadTbl.portB.request.put(BRAMRequest {
                write: False, responseOnWrite: False,
                address: {curReq.epoch, bramByte[11:6]}, datain: ? });
            cmpByteOff <= bramByte[5:0];
            Bit#(9) patSh = {truncate(cmpPos[5:0]), 3'b0};
            patByte    <= truncate(patReg >> patSh);
            cmpOneLine <= oneLineStart;
            st <= EXCmpRsp;
        end
    endrule

    // Case-fold the raw line (per byte, so folding before rotating is equivalent).
    rule doCmpRsp (st == EXCmpRsp);
        let payLine <- payloadTbl.portB.response.get;
        Bit#(512) f = 0;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(8) b = payLine[i*8+7:i*8];
            f[i*8+7:i*8] = foldCase(b);
        end
        cmpRaw <= f;
        st     <= EXCmpRot;
    endrule

    // Rotate so byte i is payload byte (cmpByteOff + i), same wrap-around as
    // before (the one-line path never reads past byte 63).  The byte-wise
    // verdict only needs byte 0, so it is decided here.
    rule doCmpRot (st == EXCmpRot);
        Bit#(512) line = 0;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(7) off   = zeroExtend(cmpByteOff) + fromInteger(i);
            Bit#(9) paySh = zeroExtend(off[5:0]) << 3;
            Bit#(8) b     = truncate(cmpRaw >> paySh);
            line[i*8+7:i*8] = b;
        end
        cmpLine <= line;
        Bit#(8) b0 = line[7:0];
        byte0Eq <= (patByte == b0);
        st      <= cmpOneLine ? EXCmpEq : EXCmpChk;
    endrule

    rule doCmpEq (st == EXCmpEq);
        Bool all = True;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(8) payB = cmpLine[i*8+7:i*8];
            Bit#(8) patB = patReg[i*8+7:i*8];
            if (cmpMask[i] == 1 && payB != patB)
                all = False;
        end
        eqAll <= all;
        st    <= EXCmpChk;
    endrule

    rule doCmpChk (st == EXCmpChk);
        if (cmpOneLine) begin
            resHit <= eqAll;
            st     <= EXEmit;
        end else if (!byte0Eq) begin
            resHit <= False;
            st     <= EXEmit;
        end else if (lastR) begin
            resHit <= True;
            st     <= EXEmit;
        end else begin
            advancePos;
            st <= EXCmpReq;
        end
    endrule

    // The only writer of outQ: every field comes from a register.
    rule doEmit (st == EXEmit);
        outQ.enq(ExMatchResult { hit: resHit,
                                 ruleId:   resHit ? curReq.req.ruleId : 0,
                                 matchPos: resHit ? pack(curStart) : 0,
                                 payLen:   curReq.payload_len,
                                 endOff:   pack(curEnd), epoch: curReq.epoch });
        st <= EXReady;
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
                             Bit#(3) epoch, Bit#(6) pay_off);
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
