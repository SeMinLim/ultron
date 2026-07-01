package GramMatcher;

import BRAM::*;
import BRAMCore::*;
import CuckooHash::*;
import FIFO::*;
import FIFOF::*;
import Vector::*;

// Banked gram matcher for bitmap candidates.
// Cuckoo values point into AssignsTable chains; isLast terminates each chain.
typedef 64 NHtBanks;

// 30b subkey = 12b of mix18(gidx0) + 18b gidx1.  Matches c_ref/mky_backup
// match.c ht_key = (gidx0 << 18) | gidx1, with bank still selected from gidx0
// alone so cuckoo bucket distribution is unchanged.
typedef 30 SubKeyBits;

typedef 16 ChainIdxBits;
typedef 65536 NChainEntries;

typedef struct {
    Bit#(16) ruleId;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
    Bool     stage2;
    Bit#(18) nextGramKey;
    Bit#(24) anchorGram;
    Bit#(5)  pad;
} RuleInfo deriving (Bits, Eq, FShow);

typedef struct {
    RuleInfo info;
    Bool     isLast;
    Bit#(7)  pad;
} ChainEntry deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(16) ruleId;
    Bit#(32) anchor;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
    Bool     stage2;
    Bit#(18) nextGramKey;
    Bit#(18) pktNextGramKey;
    Bit#(24) anchorGram;
    Bit#(24) pktAnchorGram;
} VerifyReq deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) anchor;
    Bit#(32) payLen;
    Bit#(3)  epoch;
    Bit#(6)  pay_off;
    Bit#(24) pktAnchorGram;
    Bit#(18) pktNextGramKey;
    Bool     viable2;
} GramCtx deriving (Bits);

typedef struct {
    Bool      hit;
    VerifyReq vreq;
    Bit#(32)  payLen;
    Bit#(3)   epoch;
    Bit#(6)   pay_off;
    Bool      viable2;
    Bool      lastInChain;
    Bool      bloomReject;   // True only for results killed by the bloom pre-filter
} GramResult deriving (Bits);

// --- Bloom pre-filter: 131072-bit (16KB) / k=3, mirrors c_ref/mky_backup.
// Tested before the cuckoo lookup; a reject is a guaranteed miss so we emit a
// lastInChain result directly (no false negatives by construction).
typedef 12 BloomWordBits;   // 4096 × 64b words = 262144 bits (32KB)
typedef 4  NBloomLanes;     // 4-wide bloom front-end (12 BRAM copies = 4×k3)

typedef struct {
    Bit#(32) gram;
    Bit#(24) pktAnchorGram;
    Bit#(18) pktNextGramKey;
    Bit#(32) anchor;
    Bit#(32) payLen;
    Bit#(3)  epoch;
    Bit#(6)  pay_off;
    Bool     viable2;
} BloomCtx deriving (Bits);

// Bloom hash carriers.  Multiply-shift (Fibonacci) double hash → one 64-bit
// multiply deep, so a single pipeline stage; matches the DB generator.
typedef struct { Bit#(64) key; BloomCtx ctx; } BloomReq deriving (Bits);
typedef struct { Bit#(6) b0; Bit#(6) b1; Bit#(6) b2; BloomCtx ctx; } BloomProbe deriving (Bits);

typedef Vector#(NBloomLanes, Maybe#(BloomReq))   BloomReq4;
typedef Vector#(NBloomLanes, Maybe#(BloomProbe)) BloomProbe4;
typedef struct { Bit#(3) epoch; Bit#(3) count; } BloomRejectInfo deriving (Bits);

interface GramMatcherIfc;
    // isFirst gates cuckoo insertion; isLast marks AssignsTable chain end.
    method Action loadEntry(Bit#(32) gram, Bit#(ChainIdxBits) idx,
                            RuleInfo info, Bool isFirst, Bool isLast);
    method ActionValue#(Bool) insertAck;
    // Up to NBloomLanes keys/cycle, all same epoch.  ready gates the caller.
    method Bool lookupReady;
    method Action lookupReq4(BloomReq4 reqs);
    method ActionValue#(GramResult) lookupResp;
    // Reject retirements (epoch + lane count), bypassing lookupResp.
    method ActionValue#(BloomRejectInfo) getReject;
    method Action writeBloom(Bit#(12) addr, Bit#(64) data);
    method Bool bloomBusy;
    method Bool idle;
endinterface

// Build a single-lane BloomReq from the scan-side fields (key = composite HT
// key (gram18<<18)|nextGramKey, matching the DB generator's bloom_probe).
function BloomReq mkBloomReq(Bit#(32) gram, Bit#(24) pktAnchorGram,
                             Bit#(18) pktNextGramKey, Bit#(32) anchor,
                             Bit#(32) payLen, Bit#(3) epoch, Bit#(6) pay_off,
                             Bool viable2);
    return BloomReq {
        key: zeroExtend({gram[17:0], pktNextGramKey}),
        ctx: BloomCtx {
            gram: gram, pktAnchorGram: pktAnchorGram,
            pktNextGramKey: pktNextGramKey, anchor: anchor,
            payLen: payLen, epoch: epoch, pay_off: pay_off, viable2: viable2 } };
endfunction

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    // logSz=10 → 1024 slots/table × 2 tables × 64 banks = 131,072 cuckoo slots.
    // With SubKeyBits=30 each slot stores ~47 bits; expect ~2 RAMB36 per RegFile
    // (Vivado packs 47b across two BRAMs above the 36b native width).
    Vector#(NHtBanks, CuckooHashIfc#(SubKeyBits, ChainIdxBits, 10)) banks
        <- replicateM(mkCuckooHash);

    BRAM_Configure cfgAssigns = defaultValue;
    cfgAssigns.memorySize = valueOf(NChainEntries);
    cfgAssigns.latency    = 1;
    BRAM2Port#(Bit#(ChainIdxBits), Bit#(96)) assignsTbl <- mkBRAM2Server(cfgAssigns);

    // 4 lanes × 3 probe copies = 12 bloom BRAMs.  Each 4096×64b = 262144 bits
    // (32KB) = one URAM-sized block; all 4 lanes read their k=3 probes in one
    // cycle.  portA = probe read (response FIFO keeps reads in order under
    // backpressure), portB = loader write (broadcast to all 4 lanes so every
    // lane holds an identical copy of the filter).
    BRAM_Configure cfgBloom = defaultValue;
    cfgBloom.memorySize = 4096;
    cfgBloom.latency    = 1;
    Vector#(NBloomLanes, Vector#(3, BRAM2Port#(Bit#(BloomWordBits), Bit#(64)))) bloom
        <- replicateM(replicateM(mkBRAM2Server(cfgBloom)));

    FIFOF#(Bit#(6))    pendBankQ <- mkSizedFIFOF(64);
    FIFOF#(GramCtx)    ctxQ      <- mkSizedFIFOF(64);
    FIFOF#(GramResult) outQ      <- mkSizedFIFOF(64);

    // Bloom 4-wide lockstep pipeline.
    FIFOF#(BloomReq4)   bloomReqQ  <- mkSizedFIFOF(4);  // 4 raw keys, before multiply
    FIFOF#(BloomProbe4) bloomPrQ   <- mkSizedFIFOF(4);  // 4 probe sets, awaiting BRAM
    // Passing lanes (rare) funnel here, then drain 1/cycle to the cuckoo backend.
    FIFOF#(Vector#(NBloomLanes, Maybe#(BloomCtx))) passVecQ <- mkSizedFIFOF(4);
    Reg#(Bit#(3)) passUnpackIdx <- mkReg(0);
    Reg#(Bool)    passUnpacking <- mkReg(False);
    Reg#(Vector#(NBloomLanes, Maybe#(BloomCtx))) passCur <- mkRegU;
    // Reject reports (epoch + lane count) delivered via FIFO (lossless).
    FIFOF#(BloomRejectInfo) rejectQ <- mkSizedFIFOF(8);

    // pendInsertQ preserves load-side ack ordering across banked and non-first entries.
    FIFOF#(Maybe#(Bit#(6))) pendInsertQ <- mkSizedFIFOF(8);
    FIFOF#(Bool)            ackQ        <- mkSizedFIFOF(8);

    Reg#(Bool)               chainBusy <- mkReg(False);
    Reg#(Bit#(ChainIdxBits)) chainIdx  <- mkRegU;
    Reg#(GramCtx)            chainCtx  <- mkRegU;

    function Bit#(18) mix18(Bit#(18) k);
        Bit#(18) x = k ^ (k >> 6);
        x = x ^ (x >> 7);
        x = x ^ (x << 11);
        return x;
    endfunction
    function Bit#(6) bankOf(Bit#(32) key) = mix18(key[17:0])[5:0];
    function Bit#(SubKeyBits) subKeyOf(Bit#(32) g0, Bit#(18) g1);
        return { mix18(g0[17:0])[17:6], g1 };
    endfunction

    // Multiply-shift (Fibonacci) double hash — same constants as the DB
    // generator's bloom_probe().  Top 32 bits of each 64-bit product are the
    // well-mixed half; Kirsch-Mitzenmacher derives the k=3 positions.
    Bit#(64) bloomC1 = 64'h9E3779B97F4A7C15;
    Bit#(64) bloomC2 = 64'hC2B2AE3D27D4EB4F;

    // Stage A: hash all valid lanes, issue k=3 BRAM reads per lane.
    rule bloomHash4 (bloomReqQ.notEmpty && bloomPrQ.notFull);
        let rs = bloomReqQ.first; bloomReqQ.deq;
        Vector#(NBloomLanes, Maybe#(BloomProbe)) outv = replicate(tagged Invalid);
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1) begin
            if (rs[ln] matches tagged Valid .r) begin
                Bit#(64) a = r.key * bloomC1;
                Bit#(64) b = r.key * bloomC2;
                Bit#(32) h1 = a[63:32];
                Bit#(32) h2 = b[63:32] | 32'h1;
                // n_bits = 262144 = 2^18 → low 18 bits.
                Bit#(18) p0 = truncate(h1);
                Bit#(18) p1 = truncate(h1 + h2);
                Bit#(18) p2 = truncate(h1 + h2 + h2);
                bloom[ln][0].portA.request.put(BRAMRequest {
                    write: False, responseOnWrite: False, address: p0[17:6], datain: ? });
                bloom[ln][1].portA.request.put(BRAMRequest {
                    write: False, responseOnWrite: False, address: p1[17:6], datain: ? });
                bloom[ln][2].portA.request.put(BRAMRequest {
                    write: False, responseOnWrite: False, address: p2[17:6], datain: ? });
                outv[ln] = tagged Valid BloomProbe {
                    b0: p0[5:0], b1: p1[5:0], b2: p2[5:0], ctx: r.ctx };
            end
        end
        bloomPrQ.enq(outv);
    endrule

    // Stage B: read all lanes' probes, classify pass/reject in one cycle.
    // Passes → passVecQ (drained 1/cycle by the cuckoo backend); rejects are
    // counted and reported (epoch + count) without touching the 1-wide path.
    rule bloomResp4 (bloomPrQ.notEmpty);
        let pv = bloomPrQ.first; bloomPrQ.deq;
        Vector#(NBloomLanes, Maybe#(BloomCtx)) passes = replicate(tagged Invalid);
        Bool    anyPass  = False;
        Bit#(3) rejCount = 0;
        Bit#(3) rejEpoch = 0;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1) begin
            if (pv[ln] matches tagged Valid .p) begin
                let l0 <- bloom[ln][0].portA.response.get;
                let l1 <- bloom[ln][1].portA.response.get;
                let l2 <- bloom[ln][2].portA.response.get;
                Bool pass = (l0[p.b0] == 1) && (l1[p.b1] == 1) && (l2[p.b2] == 1);
                if (pass) begin
                    passes[ln] = tagged Valid p.ctx;
                    anyPass    = True;
                end else begin
                    rejCount = rejCount + 1;
                    rejEpoch = p.ctx.epoch;
                end
            end
        end
        if (anyPass)        passVecQ.enq(passes);                              // skip all-reject
        if (rejCount != 0)  rejectQ.enq(BloomRejectInfo { epoch: rejEpoch, count: rejCount });
    endrule

    // Drain one pass-vector across cycles into the 1-wide cuckoo backend.
    rule passLoad (!passUnpacking && passVecQ.notEmpty);
        passCur       <= passVecQ.first; passVecQ.deq;
        passUnpackIdx <= 0;
        passUnpacking <= True;
    endrule

    rule passUnpack (passUnpacking);
        Bit#(3) i = passUnpackIdx;
        Bool last = (i == fromInteger(valueOf(NBloomLanes) - 1));
        if (passCur[i] matches tagged Valid .ctxv) begin
            let bank = bankOf(ctxv.gram);
            banks[bank].lookupReq(subKeyOf(ctxv.gram, ctxv.pktNextGramKey));
            pendBankQ.enq(bank);
            ctxQ.enq(GramCtx {
                anchor: ctxv.anchor, payLen: ctxv.payLen,
                epoch: ctxv.epoch, pay_off: ctxv.pay_off,
                pktAnchorGram: ctxv.pktAnchorGram,
                pktNextGramKey: ctxv.pktNextGramKey,
                viable2: ctxv.viable2 });
        end
        if (last) passUnpacking <= False;
        else      passUnpackIdx <= i + 1;
    endrule

    rule cuckooLookupResp (!chainBusy && pendBankQ.notEmpty && ctxQ.notEmpty);
        let bank = pendBankQ.first;
        let v <- banks[bank].lookupResp;
        pendBankQ.deq;
        let ctx = ctxQ.first; ctxQ.deq;
        case (v) matches
            tagged Valid .b: begin
                Bit#(ChainIdxBits) idx = unpack(b);
                assignsTbl.portB.request.put(BRAMRequest {
                    write: False, responseOnWrite: False,
                    address: idx, datain: ? });
                chainIdx  <= idx;
                chainCtx  <= ctx;
                chainBusy <= True;
            end
            tagged Invalid: begin
                outQ.enq(GramResult {
                    hit: False, vreq: unpack(0),
                    payLen:  ctx.payLen, epoch: ctx.epoch,
                    pay_off: ctx.pay_off, viable2: ctx.viable2,
                    lastInChain: True, bloomReject: False });
            end
        endcase
    endrule

    rule chainFollow (chainBusy);
        let raw <- assignsTbl.portB.response.get;
        ChainEntry ce = unpack(raw);
        outQ.enq(GramResult {
            hit: True,
            vreq: VerifyReq {
                ruleId:        ce.info.ruleId,
                anchor:        chainCtx.anchor,
                pre:           ce.info.pre,
                post:          ce.info.post,
                len:           ce.info.len,
                stage2:        ce.info.stage2,
                nextGramKey:   ce.info.nextGramKey,
                pktNextGramKey: chainCtx.pktNextGramKey,
                anchorGram:    ce.info.anchorGram,
                pktAnchorGram: chainCtx.pktAnchorGram },
            payLen:  chainCtx.payLen,
            epoch:   chainCtx.epoch,
            pay_off: chainCtx.pay_off,
            viable2: chainCtx.viable2,
            lastInChain: ce.isLast, bloomReject: False });
        if (ce.isLast) begin
            chainBusy <= False;
        end else begin
            assignsTbl.portB.request.put(BRAMRequest {
                write: False, responseOnWrite: False,
                address: chainIdx + 1, datain: ? });
            chainIdx <= chainIdx + 1;
        end
    endrule

    rule emitInsertAck (pendInsertQ.notEmpty);
        case (pendInsertQ.first) matches
            tagged Valid .bank: begin
                let ok <- banks[bank].insertAck;
                pendInsertQ.deq;
                ackQ.enq(ok);
            end
            tagged Invalid: begin
                pendInsertQ.deq;
                ackQ.enq(True);
            end
        endcase
    endrule

    method Action loadEntry(Bit#(32) gram, Bit#(ChainIdxBits) idx,
                            RuleInfo info, Bool isFirst, Bool isLast);
        ChainEntry ce = ChainEntry { info: info, isLast: isLast, pad: 0 };
        assignsTbl.portA.request.put(BRAMRequest {
            write: True, responseOnWrite: False,
            address: idx, datain: pack(ce) });
        if (isFirst) begin
            let bank = bankOf(gram);
            banks[bank].insert(subKeyOf(gram, info.nextGramKey), idx);
            pendInsertQ.enq(tagged Valid bank);
        end else begin
            pendInsertQ.enq(tagged Invalid);
        end
    endmethod

    method ActionValue#(Bool) insertAck;
        let v = ackQ.first; ackQ.deq; return v;
    endmethod

    method Bool lookupReady = bloomReqQ.notFull;

    method Action lookupReq4(BloomReq4 reqs);
        bloomReqQ.enq(reqs);
    endmethod

    method ActionValue#(GramResult) lookupResp;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method ActionValue#(BloomRejectInfo) getReject;
        let r = rejectQ.first; rejectQ.deq; return r;
    endmethod

    // Broadcast loader write to all 4 lanes × 3 copies (identical filters).
    method Action writeBloom(Bit#(12) addr, Bit#(64) data);
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            for (Integer i = 0; i < 3; i = i + 1)
                bloom[ln][i].portB.request.put(BRAMRequest {
                    write: True, responseOnWrite: False, address: addr, datain: data });
    endmethod

    // Bloom sub-pipeline has work in flight (keys awaiting multiply/probe, or
    // passes awaiting cuckoo dispatch).  Counted as its own stage in KernelMain.
    method Bool bloomBusy = bloomReqQ.notEmpty || bloomPrQ.notEmpty
                         || passVecQ.notEmpty || passUnpacking || rejectQ.notEmpty;

    method Bool idle;
        Bool allBanksIdle = True;
        for (Integer i = 0; i < valueOf(NHtBanks); i = i + 1)
            allBanksIdle = allBanksIdle && banks[i].notBusy;
        return allBanksIdle && !ctxQ.notEmpty && !outQ.notEmpty
                            && !pendBankQ.notEmpty && !pendInsertQ.notEmpty
                            && !chainBusy
                            && !bloomReqQ.notEmpty && !bloomPrQ.notEmpty
                            && !passVecQ.notEmpty && !passUnpacking
                            && !rejectQ.notEmpty;
    endmethod
endmodule

endpackage
