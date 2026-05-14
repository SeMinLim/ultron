package ExactMatch;

import FIFOF::*;
import BRAM::*;
import GramMatcher::*;
import ExactPatternTable::*;

typedef struct {
    Bool     hit;
    Bit#(16) ruleId;
    Bit#(32) matchPos;
    Bit#(32) payLen;
} ExMatchResult deriving (Bits, Eq, FShow);

typedef struct {
    VerifyReq req;
    Bit#(32)  payload_len;
    Bit#(1)   epoch;
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

    method Action putPayloadWord(Bit#(512) word, Bool last, Bit#(1) epoch);

    method Action putRequest(VerifyReq r, Bit#(32) payload_len,
                             Bit#(1) epoch, Bit#(6) pay_off);

    method ActionValue#(ExMatchResult) getResult;
    method Bool notEmpty;
    method Bool inputPending;
endinterface

module mkExactMatch#(ExactPatternTableIfc patTbl)(ExactMatchIfc);
    Integer payloadLines = 512;

    BRAM_Configure cfgPayload = defaultValue;
    cfgPayload.memorySize = payloadLines;
    cfgPayload.latency    = 1;

    BRAM2Port#(Bit#(9), Bit#(512)) payloadTbl <- mkBRAM2Server(cfgPayload);

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

        Bool bad = (r.req.len == 0 || startI < 0 || endI < 0 ||
                    startI > endI  || endI > payLenI ||
                    (endI - startI) != patLenI);
        if (bad) begin
            outQ.enq(ExMatchResult { hit: False, ruleId: 0,
                                     matchPos: 0, payLen: r.payload_len });
        end else begin
            patTbl.readPattern(truncate(r.req.ruleId));
            curReq   <= r;
            curStart <= startI;
            st       <= EXPatRsp;
        end
    endrule

    rule doPatRsp (st == EXPatRsp);
        let line <- patTbl.readResp;
        patReg <= line;
        cmpPos <= 0;
        st     <= EXCmpReq;
    endrule

    rule doCmpReq (st == EXCmpReq);
        Int#(32) payPosI    = curStart + unpack(cmpPos);
        Bit#(32) bramByte32 = pack(payPosI) + zeroExtend(curReq.pay_off);
        Bit#(8)  lineAddr   = truncate(bramByte32 >> 6);
        Bit#(6)  byteOff    = truncate(bramByte32);

        payloadTbl.portB.request.put(BRAMRequest {
            write: False, responseOnWrite: False,
            address: {curReq.epoch, lineAddr}, datain: ? });
        cmpByteOff <= byteOff;
        st <= EXCmpRsp;
    endrule

    rule doCmpRsp (st == EXCmpRsp);
        let payLine <- payloadTbl.portB.response.get;

        Bit#(9) paySh = zeroExtend(cmpByteOff) << 3;
        Bit#(8) payB  = truncate(payLine >> paySh);

        Bit#(9) patSh = {truncate(cmpPos[5:0]), 3'b0};
        Bit#(8) patB  = truncate(patReg >> patSh);

        if (patB != foldCase(payB)) begin
            outQ.enq(ExMatchResult { hit: False, ruleId: 0,
                                     matchPos: 0, payLen: curReq.payload_len });
            st <= EXReady;
        end else if (cmpPos + 1 >= zeroExtend(curReq.req.len)) begin
            outQ.enq(ExMatchResult { hit: True,  ruleId: curReq.req.ruleId,
                                     matchPos: pack(curStart), payLen: curReq.payload_len });
            st <= EXReady;
        end else begin
            cmpPos <= cmpPos + 1;
            st     <= EXCmpReq;
        end
    endrule

    method Action putPayloadWord(Bit#(512) word, Bool last, Bit#(1) epoch);
        payloadTbl.portA.request.put(BRAMRequest {
            write: True, responseOnWrite: False,
            address: {epoch, payWrLine}, datain: word });
        if (last)
            payWrLine <= 0;
        else if (payWrLine < fromInteger(payloadLines/2 - 1))
            payWrLine <= payWrLine + 1;
    endmethod

    method Action putRequest(VerifyReq r, Bit#(32) payload_len,
                             Bit#(1) epoch, Bit#(6) pay_off) if (inQ.notFull);
        inQ.enq(ExactRequest { req: r, payload_len: payload_len,
                               epoch: epoch, pay_off: pay_off });
    endmethod

    method ActionValue#(ExMatchResult) getResult;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method Bool notEmpty     = outQ.notEmpty;
    method Bool inputPending = inQ.notEmpty || (st != EXReady);
endmodule

endpackage
