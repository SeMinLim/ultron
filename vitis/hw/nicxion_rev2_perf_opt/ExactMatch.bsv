package ExactMatch;

import FIFOF::*;
import BRAM::*;
import Vector::*;
import GramMatcher::*;
import ExactPatternTable::*;
import Types::*;

typedef struct {
    Bool     hit;
    Bit#(16) ruleId;
    Bit#(32) matchPos;
    Bit#(32) payLen;
    Bit#(32) endOff;   // pattern end offset (anchor+3+post); the end-of-payload
                       // reject is deferred to drain time where the FINAL packet
                       // length is known (length arrives only on the tlast beat).
    Epoch epoch;
} ExMatchResult deriving (Bits, Eq, FShow);

typedef struct {
    VerifyReq req;
    Bit#(32)  payload_len;
    Epoch epoch;
} ExactRequest deriving (Bits, Eq, FShow);

typedef enum {
    EXReady,
    EXIssue,
    EXPatRsp,
    EXCmpReq,
    EXCmpReq2,
    EXCmpRsp,
    EXCmpRsp2,
    EXCmpRot,
    EXCmpEq,
    EXEmit
} EXState deriving (Bits, Eq, FShow);

function Bit#(8) foldCase(Bit#(8) b);
    return ((b >= 8'h41) && (b <= 8'h5A)) ? (b | 8'h20) : b;
endfunction

interface ExactMatchIfc;
    method Action putPayloadWord(Bit#(512) word, Bool last, Epoch epoch);

    method Action putRequest(VerifyReq r, Bit#(32) payload_len, Epoch epoch);

    method ActionValue#(ExMatchResult) getResult;
    method Bool notEmpty;
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
    Reg#(Int#(32))     curStart   <- mkRegU;   // data: set in doReady before use
    Reg#(Int#(32))     curEnd     <- mkRegU;
    Reg#(Bit#(512))    patReg     <- mkRegU;
    Reg#(Bool)         reqBad     <- mkRegU;   // doReady verdict, acted on in doIssue
    Reg#(Bit#(6))      cmpLineAddr <- mkRegU;  // payload line of the pattern start
    Reg#(Bit#(6))      cmpByteOff  <- mkRegU;  // start offset within that line
    Reg#(Bool)         oneLineR    <- mkRegU;  // pattern fits in the first line
    Reg#(Bit#(512))    cmpRaw      <- mkRegU;  // line L, case-folded
    Reg#(Bit#(512))    cmpRaw2     <- mkRegU;  // line L+1, case-folded (two-line only)
    Reg#(Bit#(512))    cmpLine     <- mkRegU;  // byte i = payload byte (start + i)
    Reg#(Bit#(64))     cmpMask     <- mkRegU;  // bytes that must match (idx < len, not anchor)
    Reg#(Bool)         resHit      <- mkRegU;  // result emitted by doEmit

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
        Bit#(32) start   = pack(curStart);
        Bit#(9)  lastOff = zeroExtend(start[5:0]) + zeroExtend(len);
        Bit#(64) mask    = 0;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(8) idx  = fromInteger(i);
            Bool    skip = (aIdx + 3 <= len) && (idx >= aIdx) && (idx < aIdx + 3);
            mask[i] = pack(idx < len && !skip);
        end
        cmpMask     <= mask;
        cmpLineAddr <= start[11:6];
        cmpByteOff  <= start[5:0];
        oneLineR    <= (lastOff <= 64);
        st          <= EXCmpReq;
    endrule

    function Action readLine(Bit#(6) lineAddr);
        action
            payloadTbl.portB.request.put(BRAMRequest {
                write: False, responseOnWrite: False,
                address: {curReq.epoch, lineAddr}, datain: ? });
        endaction
    endfunction

    function Bit#(512) foldLine(Bit#(512) raw);
        Bit#(512) f = 0;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(8) b = raw[i*8+7:i*8];
            f[i*8+7:i*8] = foldCase(b);
        end
        return f;
    endfunction

    rule doCmpReq (st == EXCmpReq);
        readLine(cmpLineAddr);
        st <= oneLineR ? EXCmpRsp : EXCmpReq2;
    endrule

    rule doCmpReq2 (st == EXCmpReq2);
        readLine(cmpLineAddr + 1);
        st <= EXCmpRsp;
    endrule

    rule doCmpRsp (st == EXCmpRsp);
        let raw <- payloadTbl.portB.response.get;
        cmpRaw <= foldLine(raw);
        st     <= oneLineR ? EXCmpRot : EXCmpRsp2;
    endrule

    rule doCmpRsp2 (st == EXCmpRsp2);
        let raw <- payloadTbl.portB.response.get;
        cmpRaw2 <= foldLine(raw);
        st      <= EXCmpRot;
    endrule

    // Byte i of the result is window byte (cmpByteOff + i) of {line L+1, line L}.
    // For a one-line pattern only bytes of line L are unmasked.
    //
    // A direct per-byte select is 512 independent 64:1 muxes (~10k LUT per
    // engine).  Instead shift in three radix-4 stages, off = a + 4b + 16c:
    // each stage is one 4:1 mux (one LUT6) per bit, and each stage keeps only
    // the bytes later stages can still reach (124, 112, then 64 bytes).
    rule doCmpRot (st == EXCmpRot);
        // Byte j of each stage = byte j + shift of the previous one, i.e. the
        // whole stage is one static slice of the previous stage, chosen by two
        // offset bits (a 4:1 mux per bit).  124, 112 and 64 bytes are kept.
        Bit#(1024) w = {cmpRaw2, cmpRaw};
        Bit#(992) s1 = case (cmpByteOff[1:0])        // +0..3 bytes
                           0: w[991:0];    1: w[999:8];
                           2: w[1007:16];  3: w[1015:24];
                       endcase;
        Bit#(896) s2 = case (cmpByteOff[3:2])        // +0/4/8/12 bytes
                           0: s1[895:0];   1: s1[927:32];
                           2: s1[959:64];  3: s1[991:96];
                       endcase;
        Bit#(512) s3 = case (cmpByteOff[5:4])        // +0/16/32/48 bytes
                           0: s2[511:0];   1: s2[639:128];
                           2: s2[767:256]; 3: s2[895:384];
                       endcase;
        cmpLine <= s3;
        st      <= EXCmpEq;
    endrule

    rule doCmpEq (st == EXCmpEq);
        Bool all = True;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(8) payB = cmpLine[i*8+7:i*8];
            Bit#(8) patB = patReg[i*8+7:i*8];
            if (cmpMask[i] == 1 && payB != patB)
                all = False;
        end
        resHit <= all;
        st     <= EXEmit;
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

    method Action putPayloadWord(Bit#(512) word, Bool last, Epoch epoch);
        payloadTbl.portA.request.put(BRAMRequest {
            write: True, responseOnWrite: False,
            address: {epoch, payWrLine}, datain: word });
        if (last)
            payWrLine <= 0;
        else if (payWrLine < fromInteger(linesPerEpoch - 1))
            payWrLine <= payWrLine + 1;
    endmethod

    method Action putRequest(VerifyReq r, Bit#(32) payload_len, Epoch epoch);
        inQ.enq(ExactRequest { req: r, payload_len: payload_len, epoch: epoch });
    endmethod


    method ActionValue#(ExMatchResult) getResult;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method Bool notEmpty     = outQ.notEmpty;
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

    method Action putPayloadWord(Bit#(512) word, Bool last, Epoch epoch);
        for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1)
            eng[g].putPayloadWord(word, last, epoch);
    endmethod

    method Action putRequest(VerifyReq r, Bit#(32) payload_len, Epoch epoch);
        eng[r.ruleId[1:0]].putRequest(r, payload_len, epoch);
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
endmodule

endpackage
