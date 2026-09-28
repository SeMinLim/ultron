package ExactMatch;

import FIFOF::*;
import SpecialFIFOs::*;
import BRAM::*;
import Vector::*;
import GramMatcher::*;
import ExactPatternTable::*;
import Types::*;

typedef struct {
    Bool     hit;
    Bit#(16) ruleId;
    Bit#(32) matchPos;
    Bit#(32) endOff;   // pattern end offset (anchor+3+post); KernelMain checks it
                       // against the packet's payload length (checkPomEnd).
    Epoch epoch;
} ExMatchResult deriving (Bits, Eq, FShow);

typedef struct {
    VerifyReq req;
    Epoch epoch;
} ExactRequest deriving (Bits, Eq, FShow);

// Engine pipeline carriers (see mkExactEngine).
// Only what the issue stage needs (not the whole ~300-bit request).
typedef struct {
    Bit#(16) ruleId;
    Bit#(8)  len;
    Bit#(8)  aIdx;       // anchor index within the pattern (-pre)
    Epoch    epoch;
    Int#(32) startI;
    Int#(32) endI;
    Bool     bad;
} ExPrep deriving (Bits);

// Everything the later stages need about one candidate.
typedef struct {
    Bool     bad;
    Bit#(16) ruleId;
    Epoch    epoch;
    Int#(32) startI;
    Int#(32) endI;
    Bool     oneLine;    // pattern fits in line L
    Bit#(6)  byteOff;    // start offset within line L
    Bit#(64) mask;       // bytes that must match (idx < len, not anchor)
} ExCtx deriving (Bits);

// The pattern is not carried through these stages: it waits, in candidate
// order, in patRespQ and is taken at the compare.
typedef struct { ExCtx c; Bit#(1024) win;  } ExWin  deriving (Bits);
typedef struct { ExCtx c; Bit#(512)  line; } ExLine deriving (Bits);

function Bit#(512) foldLine(Bit#(512) raw);
    Bit#(512) f = 0;
    for (Integer i = 0; i < 64; i = i + 1) begin
        Bit#(8) b = raw[i*8+7:i*8];
        f[i*8+7:i*8] = foldCase(b);
    end
    return f;
endfunction

function Bit#(8) anchorIndex(VerifyReq req);
    Int#(8) idx = -req.pre;
    return pack(idx);
endfunction

// Bank-level interface (what KernelMain uses).
interface ExactMatchIfc;
    method Action putPayloadWord(Bit#(512) word, Bool last, Epoch epoch);
    method Action putRequest(VerifyReq r, Epoch epoch);
    method ActionValue#(ExMatchResult) getResult;
    method Bool notEmpty;
endinterface

// One engine.  The pattern-table port is outside (the bank forwards patReq /
// patResp), so the engine takes no interface argument and is synthesized on
// its own -- elaborated once, one line per engine in utilization reports.
interface ExactEngineIfc;
    method Action putPayloadWord(Bit#(512) word, Bool last, Epoch epoch);
    method Action putRequest(VerifyReq r, Epoch epoch);
    method ActionValue#(ExMatchResult) getResult;
    method Bool notEmpty;
    method ActionValue#(Bit#(16)) patReq;
    method Action patResp(Bit#(512) line);
endinterface

(* synthesize *)
module mkExactEngine(ExactEngineIfc);
    Integer linesPerEpoch = 64;
    Integer payloadLines = 512;

    BRAM_Configure cfgPayload = defaultValue;
    cfgPayload.memorySize = payloadLines;
    cfgPayload.latency    = 2;

    // Eight 4KB epoch slots, addressed as {epoch[2:0], line[5:0]}.
    // Port A writes packet payload; port B verifies.
    BRAM2Port#(Bit#(9), Bit#(512)) payloadTbl <- mkBRAM2Server(cfgPayload);
    Reg#(Bit#(6)) payWrLine <- mkReg(0);

    FIFOF#(ExactRequest)  inQ      <- mkSizedFIFOF(64);
    FIFOF#(ExPrep)        prepQ    <- mkPipelineFIFOF;
    FIFOF#(ExCtx)         ctxQ     <- mkSizedFIFOF(8);    // issued, awaiting responses
    FIFOF#(Bit#(16))      patReqQ  <- mkSizedFIFOF(4);
    // Holds each non-bad candidate's pattern until its compare: deep enough for
    // the candidates between issue and cmp (ctxQ + the pipeline stages).
    FIFOF#(Bit#(512))     patRespQ <- mkSizedFIFOF(12);
    FIFOF#(ExWin)         winQ     <- mkPipelineFIFOF;
    FIFOF#(ExLine)        lineQ    <- mkPipelineFIFOF;
    FIFOF#(ExMatchResult) outQ     <- mkSizedFIFOF(64);

    Reg#(Maybe#(Bit#(9))) pend2 <- mkReg(tagged Invalid);   // line L+1 still to read
    Reg#(Bool)            haveL <- mkReg(False);            // line L collected, L+1 next
    Reg#(Bit#(512))       lineL <- mkRegU;                  // line L, case-folded

    function Action readLine(Bit#(9) addr);
        action
            payloadTbl.portB.request.put(BRAMRequest {
                write: False, responseOnWrite: False, address: addr, datain: ? });
        endaction
    endfunction

    rule prep;
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
        prepQ.enq(ExPrep { ruleId: r.req.ruleId, len: r.req.len, aIdx: anchorIndex(r.req),
                           epoch: r.epoch,
                           startI: startI, endI: endI, bad: bad });
    endrule

    rule issue (!isValid(pend2));
        let a = prepQ.first; prepQ.deq;
        Bit#(8)  len     = a.len;
        Bit#(8)  aIdx    = a.aIdx;
        Bit#(32) start   = pack(a.startI);
        Bit#(9)  lastOff = zeroExtend(start[5:0]) + zeroExtend(len);
        Bit#(64) mask    = 0;
        for (Integer i = 0; i < 64; i = i + 1) begin
            Bit#(8) idx  = fromInteger(i);
            Bool    skip = (aIdx + 3 <= len) && (idx >= aIdx) && (idx < aIdx + 3);
            mask[i] = pack(idx < len && !skip);
        end
        Bool    oneLine = (lastOff <= 64);
        Bit#(6) lineAdr = start[11:6];
        if (!a.bad) begin
            patReqQ.enq(a.ruleId);
            readLine({a.epoch, lineAdr});
            Bit#(9) addr2 = {a.epoch, lineAdr + 1};
            if (!oneLine) pend2 <= tagged Valid addr2;
        end
        ctxQ.enq(ExCtx { bad: a.bad, ruleId: a.ruleId,
                         epoch: a.epoch, startI: a.startI, endI: a.endI,
                         oneLine: oneLine, byteOff: start[5:0], mask: mask });
    endrule

    rule second (pend2 matches tagged Valid .addr);
        readLine(addr);
        pend2 <= tagged Invalid;
    endrule

    rule collect;
        let c = ctxQ.first;
        if (c.bad) begin
            ctxQ.deq;
            winQ.enq(ExWin { c: c, win: ? });
        end else begin
            let raw <- payloadTbl.portB.response.get;
            Bit#(512) f = foldLine(raw);
            if (c.oneLine || haveL) begin
                ctxQ.deq;
                haveL <= False;
                winQ.enq(ExWin { c: c, win: {f, haveL ? lineL : f} });
            end else begin
                lineL <= f;
                haveL <= True;
            end
        end
    endrule

    // Byte j of each stage = byte j + shift of the previous one: each stage is
    // one static slice of the previous, chosen by two offset bits (4:1 mux per
    // bit).  124, 112 and 64 bytes are kept.  For a one-line pattern only bytes
    // of line L are unmasked.
    rule rot;
        let x = winQ.first; winQ.deq;
        Bit#(1024) w   = x.win;
        Bit#(6)    off = x.c.byteOff;
        Bit#(992) s1 = case (off[1:0])        // +0..3 bytes
                           0: w[991:0];    1: w[999:8];
                           2: w[1007:16];  3: w[1015:24];
                       endcase;
        Bit#(896) s2 = case (off[3:2])        // +0/4/8/12 bytes
                           0: s1[895:0];   1: s1[927:32];
                           2: s1[959:64];  3: s1[991:96];
                       endcase;
        Bit#(512) s3 = case (off[5:4])        // +0/16/32/48 bytes
                           0: s2[511:0];   1: s2[639:128];
                           2: s2[767:256]; 3: s2[895:384];
                       endcase;
        lineQ.enq(ExLine { c: x.c, line: s3 });
    endrule

    // The only writer of outQ.  A bad candidate never requested a pattern.
    rule cmp;
        let x = lineQ.first; lineQ.deq;
        let c = x.c;
        Bool all = True;
        if (!c.bad) begin
            let pat = patRespQ.first; patRespQ.deq;
            for (Integer i = 0; i < 64; i = i + 1) begin
                Bit#(8) payB = x.line[i*8+7:i*8];
                Bit#(8) patB = pat[i*8+7:i*8];
                if (c.mask[i] == 1 && payB != patB)
                    all = False;
            end
        end
        Bool hit = !c.bad && all;
        outQ.enq(ExMatchResult { hit:      hit,
                                 ruleId:   hit ? c.ruleId : 0,
                                 matchPos: hit ? pack(c.startI) : 0,
                                 endOff:   pack(c.endI), epoch: c.epoch });
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

    method Action putRequest(VerifyReq r, Epoch epoch);
        inQ.enq(ExactRequest { req: r, epoch: epoch });
    endmethod

    method ActionValue#(ExMatchResult) getResult;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method Bool notEmpty = outQ.notEmpty;

    method ActionValue#(Bit#(16)) patReq;
        let v = patReqQ.first; patReqQ.deq; return v;
    endmethod

    method Action patResp(Bit#(512) line);
        patRespQ.enq(line);
    endmethod
endmodule

// Banked by ruleId[PortBits-1:0]; each engine owns a pattern read port and a
// payload copy.  NReadPorts (ExactPatternTable) sets the engine count.
module mkExactMatchParallel#(ExactPatternTableIfc patTbl)(ExactMatchIfc);
    Vector#(NReadPorts, ExactEngineIfc) eng <- replicateM(mkExactEngine);

    for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1) begin
        rule fwdPatReq;
            let id <- eng[g].patReq;
            patTbl.rd[g].readPattern(id);
        endrule
        rule fwdPatResp;
            let l <- patTbl.rd[g].readResp;
            eng[g].patResp(l);
        endrule
    end

    // Round-robin over engines with a result, starting after the last one served.
    Reg#(Bit#(PortBits)) rr <- mkReg(0);

    function Bool engReady(Integer g) = eng[g].notEmpty;
    Vector#(NReadPorts, Bool) ready = genWith(engReady);

    // Round-robin collect into one registered result queue (keeps the N-way
    // result mux off the caller's rule).  First ready engine at or after rr:
    // rotate the ready bits so rr is bit 0 and take the lowest set bit; each
    // engine is dequeued under its own static select.  Results waiting here are
    // still counted as in-flight exact work (the caller decrements at getResult).
    FIFOF#(ExMatchResult) resQ <- mkFIFOF;

    rule collect (pack(ready) != 0);
        Bit#(NReadPorts)         rb   = pack(ready);
        Bit#(TAdd#(PortBits, 1)) left = fromInteger(valueOf(NReadPorts)) - zeroExtend(rr);
        Bit#(NReadPorts)         rot  = (rb >> rr) | (rb << left);
        Bit#(PortBits)           sel  = rr + truncate(pack(countZerosLSB(rot)));
        for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1)
            if (sel == fromInteger(g)) begin
                let x <- eng[g].getResult;
                resQ.enq(x);
            end
        rr <= sel + 1;
    endrule

    method Action putPayloadWord(Bit#(512) word, Bool last, Epoch epoch);
        for (Integer g = 0; g < valueOf(NReadPorts); g = g + 1)
            eng[g].putPayloadWord(word, last, epoch);
    endmethod

    method Action putRequest(VerifyReq r, Epoch epoch);
        Bit#(PortBits) g = truncate(r.ruleId);
        eng[g].putRequest(r, epoch);
    endmethod

    method ActionValue#(ExMatchResult) getResult;
        let v = resQ.first; resQ.deq; return v;
    endmethod

    method Bool notEmpty = resQ.notEmpty;
endmodule

endpackage
