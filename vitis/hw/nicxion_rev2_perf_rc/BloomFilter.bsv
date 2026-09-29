package BloomFilter;

import BRAM::*;
import FIFOF::*;
import Vector::*;
import Types::*;

typedef 12 BloomWordBits;   // 4096 x 64b words = 262144 bits (32KB)
typedef 4  NBloomLanes;

typedef struct {
    Bit#(32) gram;
    AnchorGram pktAnchorGram;
    GramKey pktNextGramKey;
    Bit#(32) anchor;
    Epoch    epoch;
} BloomCtx deriving (Bits);

typedef struct { Bit#(64) key; BloomCtx ctx; } BloomReq deriving (Bits);
typedef struct { Bit#(6) b0; Bit#(6) b1; Bit#(6) b2; BloomCtx ctx; } BloomProbe deriving (Bits);

typedef Vector#(NBloomLanes, Maybe#(BloomReq))   BloomReq4;
typedef Vector#(NBloomLanes, Maybe#(BloomProbe)) BloomProbe4;
typedef Vector#(NBloomLanes, Maybe#(BloomCtx))   BloomPass4;
typedef Bit#(36) BloomKey;   // {gram key, next-gram key}, as probed

typedef struct {
    Epoch            epoch;
    Bit#(3)          count;
    Maybe#(BloomKey) key;
} BloomRejectInfo deriving (Bits);

function BloomReq mkBloomReq(Bit#(32) gram, AnchorGram pktAnchorGram,
                             GramKey pktNextGramKey, Bit#(32) anchor,
                             Epoch epoch);
    return BloomReq {
        key: zeroExtend({gram[17:0], pktNextGramKey}),
        ctx: BloomCtx {
            gram: gram, pktAnchorGram: pktAnchorGram,
            pktNextGramKey: pktNextGramKey, anchor: anchor,
            epoch: epoch } };
endfunction

typedef struct {
    Vector#(NBloomLanes, Maybe#(BloomCtx)) ctx;
    Vector#(NBloomLanes, Bit#(36))         key;
} HashIn deriving (Bits);
typedef struct {
    Vector#(NBloomLanes, Maybe#(BloomCtx)) ctx;
    Vector#(NBloomLanes, Bit#(50))         aL;   // kL * C1[49:0]  mod 2^50
    Vector#(NBloomLanes, Bit#(32))         aH;   // kH * C1[31:0]  mod 2^32
    Vector#(NBloomLanes, Bit#(50))         bL;
    Vector#(NBloomLanes, Bit#(32))         bH;
} HashPart deriving (Bits);
typedef struct {
    Vector#(NBloomLanes, Maybe#(BloomCtx)) ctx;
    Vector#(NBloomLanes, Bit#(18))         a;
    Vector#(NBloomLanes, Bit#(18))         b;
} HashSum deriving (Bits);
typedef struct {
    Vector#(NBloomLanes, Maybe#(BloomProbe)) probe;
    Vector#(NBloomLanes, Vector#(3, Bit#(BloomWordBits))) addr;
} HashOut deriving (Bits);

interface BloomFilterIfc;
    method Bool   reqReady;
    method Action req(BloomReq4 reqs);
    method ActionValue#(BloomPass4)      pass;
    method Bool                          passReady;   // a pass vector is waiting
    method ActionValue#(BloomRejectInfo) reject;
    method Action write(Bit#(BloomWordBits) addr, Bit#(64) data);
endinterface

(* synthesize *)
module mkBloomFilter(BloomFilterIfc);
    BRAM_Configure cfgBloom = defaultValue;
    cfgBloom.memorySize = 4096;
    cfgBloom.latency    = 2;
    Vector#(NBloomLanes, Vector#(3, BRAM2Port#(Bit#(BloomWordBits), Bit#(64)))) bloom
        <- replicateM(replicateM(mkBRAM2Server(cfgBloom)));

    FIFOF#(BloomReq4)   bloomReqQ <- mkSizedFIFOF(4);  // raw keys, before multiply
    FIFOF#(BloomProbe4) bloomPrQ  <- mkSizedFIFOF(4);  // probe sets awaiting BRAM
    FIFOF#(Vector#(NBloomLanes, Maybe#(Tuple2#(Bool, BloomCtx)))) verdictQ <- mkFIFOF;
    FIFOF#(BloomPass4)      passVecQ <- mkSizedFIFOF(4);
    FIFOF#(BloomRejectInfo) rejectQ  <- mkSizedFIFOF(8);

    Reg#(Bool)                 hashInV   <- mkReg(False);
    Reg#(HashIn)               hashIn    <- mkRegU;
    Vector#(4, Reg#(Bool))     hashProdV <- replicateM(mkReg(False));
    Vector#(2, Reg#(HashPart)) hashPart  <- replicateM(mkRegU);
    Vector#(2, Reg#(HashSum))  hashSum   <- replicateM(mkRegU);
    FIFOF#(HashOut)            hashOutQ  <- mkSizedFIFOF(4);

    Bit#(64) bloomC1 = 64'h9E3779B97F4A7C15;
    Bit#(64) bloomC2 = 64'hC2B2AE3D27D4EB4F;

    Bool hashLastV = hashProdV[3];
    rule bloomHashAdvance (!hashLastV || hashOutQ.notFull);
        if (hashLastV) begin
            HashSum hp = hashSum[1];
            HashOut o = HashOut { probe: replicate(tagged Invalid), addr: replicate(replicate(0)) };
            for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
                if (hp.ctx[ln] matches tagged Valid .c) begin
                    Bit#(18) h1 = hp.a[ln];
                    Bit#(18) h2 = hp.b[ln] | 18'h1;
                    Bit#(18) p0 = h1;
                    Bit#(18) p1 = h1 + h2;
                    Bit#(18) p2 = h1 + (h2 << 1);
                    o.addr[ln][0] = p0[17:6]; o.addr[ln][1] = p1[17:6]; o.addr[ln][2] = p2[17:6];
                    o.probe[ln] = tagged Valid BloomProbe { b0: p0[5:0], b1: p1[5:0], b2: p2[5:0], ctx: c };
                end
            hashOutQ.enq(o);
        end
        for (Integer i = 3; i > 0; i = i - 1)
            hashProdV[i] <= hashProdV[i - 1];
        hashPart[1] <= hashPart[0];
        hashSum[1]  <= hashSum[0];
        HashPart pp = hashPart[1];
        HashSum  ns = ?;
        ns.ctx = pp.ctx;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1) begin
            Bit#(50) pa = pp.aL[ln] + {pp.aH[ln], 18'b0};
            Bit#(50) pb = pp.bL[ln] + {pp.bH[ln], 18'b0};
            ns.a[ln] = pa[49:32];
            ns.b[ln] = pb[49:32];
        end
        hashSum[0] <= ns;
        HashPart np = ?;
        np.ctx = hashIn.ctx;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1) begin
            Bit#(50) kL = zeroExtend(hashIn.key[ln][17:0]);
            Bit#(32) kH = zeroExtend(hashIn.key[ln][35:18]);
            np.aL[ln] = kL * bloomC1[49:0];
            np.aH[ln] = kH * bloomC1[31:0];
            np.bL[ln] = kL * bloomC2[49:0];
            np.bH[ln] = kH * bloomC2[31:0];
        end
        hashProdV[0] <= hashInV;
        hashPart[0]  <= np;
        if (bloomReqQ.notEmpty) begin
            let rs = bloomReqQ.first; bloomReqQ.deq;
            HashIn hi = ?;
            for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
                case (rs[ln]) matches
                    tagged Valid .r: begin hi.ctx[ln] = tagged Valid r.ctx; hi.key[ln] = r.key[35:0]; end
                    tagged Invalid:  begin hi.ctx[ln] = tagged Invalid;     hi.key[ln] = 0;           end
                endcase
            hashIn  <= hi;
            hashInV <= True;
        end else
            hashInV <= False;
    endrule

    rule bloomIssue4;
        let o = hashOutQ.first; hashOutQ.deq;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            if (isValid(o.probe[ln]))
                for (Integer k = 0; k < 3; k = k + 1)
                    bloom[ln][k].portA.request.put(BRAMRequest {
                        write: False, responseOnWrite: False, address: o.addr[ln][k], datain: ? });
        bloomPrQ.enq(o.probe);
    endrule

    rule bloomResp4;
        let pv = bloomPrQ.first; bloomPrQ.deq;
        Vector#(NBloomLanes, Maybe#(Tuple2#(Bool, BloomCtx))) vv = replicate(tagged Invalid);
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1) begin
            if (pv[ln] matches tagged Valid .p) begin
                let l0 <- bloom[ln][0].portA.response.get;
                let l1 <- bloom[ln][1].portA.response.get;
                let l2 <- bloom[ln][2].portA.response.get;
                Bool pass = (l0[p.b0] == 1) && (l1[p.b1] == 1) && (l2[p.b2] == 1);
                vv[ln] = tagged Valid tuple2(pass, p.ctx);
            end
        end
        verdictQ.enq(vv);
    endrule

    rule bloomClassify4;
        let vv = verdictQ.first; verdictQ.deq;
        BloomPass4 passes   = replicate(tagged Invalid);
        Bool       anyPass  = False;
        Bit#(3)    rejCount = 0;
        Epoch      rejEpoch = 0;
        Maybe#(BloomKey) rejKey = tagged Invalid;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            if (vv[ln] matches tagged Valid {.pass, .c}) begin
                if (pass) begin
                    passes[ln] = tagged Valid c;
                    anyPass    = True;
                end else begin
                    rejCount = rejCount + 1;
                    rejEpoch = c.epoch;
                    BloomKey k = { c.gram[17:0], c.pktNextGramKey };
                    rejKey   = tagged Valid k;
                end
            end
        if (anyPass)        passVecQ.enq(passes);                              // skip all-reject
        if (rejCount != 0)  rejectQ.enq(BloomRejectInfo { epoch: rejEpoch, count: rejCount, key: rejKey });
    endrule

    method Bool reqReady = bloomReqQ.notFull;

    method Action req(BloomReq4 reqs);
        bloomReqQ.enq(reqs);
    endmethod

    method Bool passReady = passVecQ.notEmpty;

    method ActionValue#(BloomPass4) pass;
        let v = passVecQ.first; passVecQ.deq; return v;
    endmethod

    method ActionValue#(BloomRejectInfo) reject;
        let r = rejectQ.first; rejectQ.deq; return r;
    endmethod

    method Action write(Bit#(BloomWordBits) addr, Bit#(64) data);
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            for (Integer i = 0; i < 3; i = i + 1)
                bloom[ln][i].portB.request.put(BRAMRequest {
                    write: True, responseOnWrite: False, address: addr, datain: data });
    endmethod
endmodule

endpackage
