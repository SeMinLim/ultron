import FIFO::*;
import FIFOF::*;
import BRAM::*;
import HashTable::*;
import StaticDbMeta::*;

typedef struct {
    VerifyRequest req;
    Bit#(32) payload_len;
} ExactRequest deriving (Bits, Eq, FShow);

typedef enum {
    EXReady,
    EXMetaRsp,
    EXCmpReq,
    EXCmpRsp
} EXState deriving (Bits, Eq, FShow);

interface ExactMatchIfc;
    method Action putPayloadByte(Bit#(8) b, Bool last);
    method Action putRequest(VerifyRequest r, Bit#(32) payload_len);
    method ActionValue#(Bool) getResult;

    method Bool notEmpty;
    method Bool inputPending;
endinterface

module mkExactMatch(ExactMatchIfc);
    Integer assignCapacity = staticGramdbAssignCountInt;
    Integer patternBytes   = staticExactPatternBytesInt;
    Integer payloadBytes   = 16384;

    BRAM_Configure cfgAssign = defaultValue;
    cfgAssign.memorySize = assignCapacity;
    cfgAssign.latency    = 2;

    BRAM_Configure cfgPre = cfgAssign;
    cfgPre.loadFormat = tagged Hex "generated/ruledb_pre.hex";
    BRAM_Configure cfgPost = cfgAssign;
    cfgPost.loadFormat = tagged Hex "generated/ruledb_post.hex";
    BRAM_Configure cfgLen = cfgAssign;
    cfgLen.loadFormat = tagged Hex "generated/ruledb_len.hex";

    BRAM_Configure cfgPat = defaultValue;
    cfgPat.memorySize = patternBytes;
    cfgPat.latency    = 2;
    cfgPat.loadFormat = tagged Hex "generated/ruledb_pat.hex";

    BRAM_Configure cfgPayload = defaultValue;
    cfgPayload.memorySize = payloadBytes;
    cfgPayload.latency    = 2;

    BRAM1Port#(Bit#(16), Bit#(32)) preTbl     <- mkBRAM1Server(cfgPre);
    BRAM1Port#(Bit#(16), Bit#(32)) postTbl    <- mkBRAM1Server(cfgPost);
    BRAM1Port#(Bit#(16), Bit#(32)) lenTbl     <- mkBRAM1Server(cfgLen);
    BRAM1Port#(Bit#(22), Bit#(8))  patTbl     <- mkBRAM1Server(cfgPat);
    BRAM2Port#(Bit#(14), Bit#(8))  payloadTbl <- mkBRAM2Server(cfgPayload);

    FIFOF#(ExactRequest) inQ  <- mkSizedFIFOF(1024);
    FIFOF#(Bool)         outQ <- mkSizedFIFOF(1024);

    Reg#(EXState) st <- mkReg(EXReady);

    Bit#(32) nAssigns = fromInteger(assignCapacity);
    Reg#(Bit#(14)) payWrIdx <- mkReg(0);

    Reg#(ExactRequest) curReq    <- mkRegU;
    Reg#(Bit#(16))     curAssign <- mkReg(0);
    Reg#(Int#(32))     curStart  <- mkReg(0);
    Reg#(Bit#(32))     curPatLen <- mkReg(0);
    Reg#(Bit#(32))     cmpPos    <- mkReg(0);

    rule doMetaReq (st == EXReady && inQ.notEmpty);
        let r = inQ.first;
        inQ.deq;

        Bit#(32) idx32 = r.req.base + r.req.candIdx;
        let maxN = fromInteger(assignCapacity);

        if (idx32 >= nAssigns || idx32 >= maxN) begin
            outQ.enq(False);
        end else begin
            Bit#(16) idx = truncate(idx32);

            preTbl.portA.request.put(BRAMRequest {
                write           : False,
                responseOnWrite : False,
                address         : idx,
                datain          : ?
            });
            postTbl.portA.request.put(BRAMRequest {
                write           : False,
                responseOnWrite : False,
                address         : idx,
                datain          : ?
            });
            lenTbl.portA.request.put(BRAMRequest {
                write           : False,
                responseOnWrite : False,
                address         : idx,
                datain          : ?
            });

            curReq    <= r;
            curAssign <= idx;
            st        <= EXMetaRsp;
        end
    endrule

    rule doMetaRsp (st == EXMetaRsp);
        let preBits  <- preTbl.portA.response.get;
        let postBits <- postTbl.portA.response.get;
        let lenBits  <- lenTbl.portA.response.get;

        Int#(32) anchorI     = unpack(curReq.req.anchor);
        Int#(32) preI        = unpack(preBits);
        Int#(32) postI       = unpack(postBits);
        Int#(32) startI      = anchorI + preI;
        Int#(32) endI        = anchorI + 3 + postI;
        Int#(32) patLenI     = unpack(lenBits);
        Int#(32) payloadLenI = unpack(curReq.payload_len);

        if (lenBits == 0 ||
            startI < 0 || endI < 0 ||
            startI > endI ||
            endI > payloadLenI ||
            (endI - startI) != patLenI) begin
            outQ.enq(False);
            st <= EXReady;
        end else begin
            curStart  <= startI;
            curPatLen <= lenBits;
            cmpPos    <= 0;
            st        <= EXCmpReq;
        end
    endrule

    rule doCmpReq (st == EXCmpReq);
        Bit#(32) patAddr32 = (zeroExtend(curAssign) << 6) + cmpPos;
        Bit#(22) patAddr   = truncate(patAddr32);

        Int#(32) payPosI   = curStart + unpack(cmpPos);
        Bit#(14) payAddr   = truncate(pack(payPosI));

        patTbl.portA.request.put(BRAMRequest {
            write           : False,
            responseOnWrite : False,
            address         : patAddr,
            datain          : ?
        });

        payloadTbl.portB.request.put(BRAMRequest {
            write           : False,
            responseOnWrite : False,
            address         : payAddr,
            datain          : ?
        });

        st <= EXCmpRsp;
    endrule

    rule doCmpRsp (st == EXCmpRsp);
        let patB <- patTbl.portA.response.get;
        let payB <- payloadTbl.portB.response.get;

        if (patB != payB) begin
            outQ.enq(False);
            st <= EXReady;
        end else if (cmpPos + 1 >= curPatLen) begin
            outQ.enq(True);
            st <= EXReady;
        end else begin
            cmpPos <= cmpPos + 1;
            st <= EXCmpReq;
        end
    endrule

    method Action putPayloadByte(Bit#(8) b, Bool last);
        payloadTbl.portA.request.put(BRAMRequest {
            write           : True,
            responseOnWrite : False,
            address         : payWrIdx,
            datain          : b
        });

        if (last) begin
            payWrIdx <= 0;
        end else begin
            payWrIdx <= payWrIdx + 1;
        end
    endmethod

    method Action putRequest(VerifyRequest r, Bit#(32) payload_len)
            if (inQ.notFull);
        inQ.enq(ExactRequest { req: r, payload_len: payload_len });
    endmethod

    method ActionValue#(Bool) getResult;
        let v = outQ.first;
        outQ.deq;
        return v;
    endmethod

    method Bool notEmpty     = outQ.notEmpty;
    method Bool inputPending = inQ.notEmpty || (st != EXReady);
endmodule
