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

typedef 13 ChainIdxBits;
typedef 8192 NChainEntries;

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

// Everything needed to either issue the cuckoo lookup or emit a miss once the
// bloom verdict is known.
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

// 4-wide lockstep carriers: one entry holds up to NBloomLanes lanes, all from
// the same doScan batch (same epoch).  Invalid lanes are padding bubbles.
typedef Vector#(NBloomLanes, Maybe#(BloomReq))   BloomReq4;
typedef Vector#(NBloomLanes, Maybe#(BloomProbe)) BloomProbe4;
// Reject report: epoch of the batch + how many lanes rejected this cycle.
typedef struct { Bit#(3) epoch; Bit#(3) count; } BloomRejectInfo deriving (Bits);

// A DB-load entry, queued so loadEntry's ready signal is one local FIFO flag
// (bank index and subkey are computed on the way in).
typedef struct {
    Bit#(6)             bank;
    Bit#(SubKeyBits)    subKey;
    Bit#(ChainIdxBits)  idx;
    ChainEntry          ce;
    Bool                isFirst;
} LoadReq deriving (Bits);

// A cuckoo lookup whose bank is already decided, one register stage ahead of
// the 64-way bank dispatch.
typedef struct {
    Bit#(6)             bank;
    Bit#(SubKeyBits)    subKey;
    GramCtx             ctx;
} DispReq deriving (Bits);

// Bloom hash pipeline stage: raw keys (stage 0) or products (later stages).
typedef struct {
    Vector#(NBloomLanes, Maybe#(BloomCtx)) ctx;
    Vector#(NBloomLanes, Bit#(36))         key;
} HashIn deriving (Bits);
typedef struct {
    Vector#(NBloomLanes, Maybe#(BloomCtx)) ctx;
    Vector#(NBloomLanes, Bit#(64))         a;
    Vector#(NBloomLanes, Bit#(64))         b;
} HashProd deriving (Bits);
// Probe addresses ready to issue.
typedef struct {
    Vector#(NBloomLanes, Maybe#(BloomProbe)) probe;
    Vector#(NBloomLanes, Vector#(3, Bit#(BloomWordBits))) addr;
} HashOut deriving (Bits);

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
    // logSz=9 → 512 slots/table × 2 tables × 64 banks = 65,536 cuckoo slots.
    // NOT sized by chain-entry count: the gram hash spreads unevenly across the
    // 64 banks, so the busiest bank decides.  At 5k rules (4,678 chain heads) the
    // busiest bank holds ~168 keys; logSz=7 (128/table) saturated it and cuckoo
    // silently dropped 702 keys after hitting MaxEvictions -> missed matches that
    // only appear at large rulesets (451 rules passed, 5,000 failed).
    // Simulated key loss: logSz=7 -> 702, 8 -> 17, 9 -> 0.
    // With SubKeyBits=30 each slot stores 44 bits (1 valid + 30 key + 13 val).
    Vector#(NHtBanks, CuckooHashIfc#(SubKeyBits, ChainIdxBits, 9)) banks
        <- replicateM(mkCuckooHash);

    BRAM_Configure cfgAssigns = defaultValue;
    cfgAssigns.memorySize = valueOf(NChainEntries);
    cfgAssigns.latency    = 2;   // output register (250 MHz); chains are ~1 entry long
    BRAM2Port#(Bit#(ChainIdxBits), Bit#(96)) assignsTbl <- mkBRAM2Server(cfgAssigns);

    // 4 lanes × 3 probe copies = 12 bloom BRAMs.  Each 4096×64b = 262144 bits
    // (32KB) = one URAM-sized block; all 4 lanes read their k=3 probes in one
    // cycle.  portA = probe read (response FIFO keeps reads in order under
    // backpressure), portB = loader write (broadcast to all 4 lanes so every
    // lane holds an identical copy of the filter).
    BRAM_Configure cfgBloom = defaultValue;
    cfgBloom.memorySize = 4096;
    cfgBloom.latency    = 2;   // output register: the 4096-deep cascade feeds fabric at 250 MHz
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

    FIFOF#(LoadReq)  loadQ <- mkFIFOF;
    FIFOF#(DispReq)  dispQ <- mkFIFOF;

    // Two-level bank fan-out for 250 MHz: 8 groups x 8 banks, so no single
    // enable or ready select spans all 64 banks.  Per-bank order is preserved
    // (each group queue is FIFO), which is all the in-order collection needs.
    Vector#(8, FIFOF#(Tuple2#(Bit#(3), Bit#(SubKeyBits))))
        lkGrpQ  <- replicateM(mkFIFOF);
    Vector#(8, FIFOF#(Tuple3#(Bit#(3), Bit#(SubKeyBits), Bit#(ChainIdxBits))))
        insGrpQ <- replicateM(mkFIFOF);
    // Cuckoo response, registered before the chain/miss decision.
    FIFOF#(Tuple2#(Maybe#(Bit#(ChainIdxBits)), GramCtx)) lkRespQ <- mkFIFOF;
    // Chain entries, registered before they are formatted into outQ.
    FIFOF#(Tuple2#(ChainEntry, GramCtx)) chainOutQ <- mkFIFOF;

    // Bloom hash pipeline.  The 36x64 multiply maps to a 4-DSP cascade; the
    // product registers below (hashProd[0..]) sit directly after the multiply
    // so synthesis can pull them into the cascade (MREG/PREG).  All stages
    // advance together on one enable; hashOutQ absorbs the stall.
    Integer nProdRegs = 4;
    Reg#(Bool)                           hashInV   <- mkReg(False);
    Reg#(HashIn)                         hashIn    <- mkRegU;
    Vector#(4, Reg#(Bool))               hashProdV <- replicateM(mkReg(False));
    Vector#(4, Reg#(HashProd))           hashProd  <- replicateM(mkRegU);
    FIFOF#(HashOut)                      hashOutQ  <- mkSizedFIFOF(4);
    // Bloom response: bit-selected verdicts registered before classification.
    FIFOF#(Vector#(NBloomLanes, Maybe#(Tuple2#(Bool, BloomCtx)))) verdictQ <- mkFIFOF;

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

    // Stage A: multiply pipeline.  Fires whenever the last stage can drain,
    // shifting bubbles too, so the enable is one registered FIFO flag.
    Bool hashLastV = hashProdV[nProdRegs - 1];
    rule bloomHashAdvance (!hashLastV || hashOutQ.notFull);
        // Drain: product -> k=3 probe positions (only the low 18 bits matter).
        if (hashLastV) begin
            HashProd hp = hashProd[nProdRegs - 1];
            HashOut o = HashOut { probe: replicate(tagged Invalid), addr: replicate(replicate(0)) };
            for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
                if (hp.ctx[ln] matches tagged Valid .c) begin
                    Bit#(18) h1 = hp.a[ln][49:32];
                    Bit#(18) h2 = hp.b[ln][49:32] | 18'h1;
                    Bit#(18) p0 = h1;
                    Bit#(18) p1 = h1 + h2;
                    Bit#(18) p2 = h1 + (h2 << 1);
                    o.addr[ln][0] = p0[17:6]; o.addr[ln][1] = p1[17:6]; o.addr[ln][2] = p2[17:6];
                    o.probe[ln] = tagged Valid BloomProbe { b0: p0[5:0], b1: p1[5:0], b2: p2[5:0], ctx: c };
                end
            hashOutQ.enq(o);
        end
        // Shift product registers.
        for (Integer i = nProdRegs - 1; i > 0; i = i - 1) begin
            hashProdV[i] <= hashProdV[i - 1];
            hashProd[i]  <= hashProd[i - 1];
        end
        // Multiply: raw keys -> products.
        HashProd np = ?;
        np.ctx = hashIn.ctx;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1) begin
            np.a[ln] = zeroExtend(hashIn.key[ln]) * bloomC1;
            np.b[ln] = zeroExtend(hashIn.key[ln]) * bloomC2;
        end
        hashProdV[0] <= hashInV;
        hashProd[0]  <= np;
        // Load raw keys.
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

    // Stage B: issue the registered probe addresses.
    rule bloomIssue4;
        let o = hashOutQ.first; hashOutQ.deq;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            if (isValid(o.probe[ln]))
                for (Integer k = 0; k < 3; k = k + 1)
                    bloom[ln][k].portA.request.put(BRAMRequest {
                        write: False, responseOnWrite: False, address: o.addr[ln][k], datain: ? });
        bloomPrQ.enq(o.probe);
    endrule

    // Stage C: read all lanes' probes and register the per-lane verdict.
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

    // Stage D: passes -> passVecQ (drained 1/cycle by the cuckoo backend);
    // rejects are counted and reported (epoch + count) without touching it.
    rule bloomClassify4;
        let vv = verdictQ.first; verdictQ.deq;
        Vector#(NBloomLanes, Maybe#(BloomCtx)) passes = replicate(tagged Invalid);
        Bool    anyPass  = False;
        Bit#(3) rejCount = 0;
        Bit#(3) rejEpoch = 0;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            if (vv[ln] matches tagged Valid {.pass, .c}) begin
                if (pass) begin
                    passes[ln] = tagged Valid c;
                    anyPass    = True;
                end else begin
                    rejCount = rejCount + 1;
                    rejEpoch = c.epoch;
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
        if (passCur[i] matches tagged Valid .ctxv)
            dispQ.enq(DispReq {
                bank:   bankOf(ctxv.gram),
                subKey: subKeyOf(ctxv.gram, ctxv.pktNextGramKey),
                ctx: GramCtx {
                    anchor: ctxv.anchor, payLen: ctxv.payLen,
                    epoch: ctxv.epoch, pay_off: ctxv.pay_off,
                    pktAnchorGram: ctxv.pktAnchorGram,
                    pktNextGramKey: ctxv.pktNextGramKey,
                    viable2: ctxv.viable2 } });
        if (last) passUnpacking <= False;
        else      passUnpackIdx <= i + 1;
    endrule

    // Bank index is registered here, so the 64-way ready select is shallow.
    rule dispatchLookup;
        let d = dispQ.first; dispQ.deq;
        for (Integer g = 0; g < 8; g = g + 1)
            if (d.bank[5:3] == fromInteger(g))
                lkGrpQ[g].enq(tuple2(d.bank[2:0], d.subKey));
        pendBankQ.enq(d.bank);
        ctxQ.enq(d.ctx);
    endrule

    for (Integer g = 0; g < 8; g = g + 1)
        rule dispatchBank;
            match { .lo, .k } = lkGrpQ[g].first; lkGrpQ[g].deq;
            for (Integer j = 0; j < 8; j = j + 1)
                if (lo == fromInteger(j)) banks[g * 8 + j].lookupReq(k);
        endrule

    // Collect in issue order (pendBankQ), register, then decide.
    rule collectLookup;
        let bank = pendBankQ.first; pendBankQ.deq;
        let v <- banks[bank].lookupResp;
        let ctx = ctxQ.first; ctxQ.deq;
        lkRespQ.enq(tuple2(v, ctx));
    endrule

    rule cuckooLookupResp (!chainBusy);
        match { .v, .ctx } = lkRespQ.first; lkRespQ.deq;
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

    // Only the isLast bit feeds the next-request decision; the entry itself is
    // registered in chainOutQ and formatted into outQ one cycle later.
    rule chainFollow (chainBusy);
        let raw <- assignsTbl.portB.response.get;
        ChainEntry ce = unpack(raw);
        chainOutQ.enq(tuple2(ce, chainCtx));
        if (ce.isLast) begin
            chainBusy <= False;
        end else begin
            assignsTbl.portB.request.put(BRAMRequest {
                write: False, responseOnWrite: False,
                address: chainIdx + 1, datain: ? });
            chainIdx <= chainIdx + 1;
        end
    endrule

    rule emitChain;
        match { .ce, .cc } = chainOutQ.first; chainOutQ.deq;
        outQ.enq(GramResult {
            hit: True,
            vreq: VerifyReq {
                ruleId:        ce.info.ruleId,
                anchor:        cc.anchor,
                pre:           ce.info.pre,
                post:          ce.info.post,
                len:           ce.info.len,
                stage2:        ce.info.stage2,
                nextGramKey:   ce.info.nextGramKey,
                pktNextGramKey: cc.pktNextGramKey,
                anchorGram:    ce.info.anchorGram,
                pktAnchorGram: cc.pktAnchorGram },
            payLen:  cc.payLen,
            epoch:   cc.epoch,
            pay_off: cc.pay_off,
            viable2: cc.viable2,
            lastInChain: ce.isLast, bloomReject: False });
    endrule

    rule doLoad;
        let l = loadQ.first; loadQ.deq;
        assignsTbl.portA.request.put(BRAMRequest {
            write: True, responseOnWrite: False,
            address: l.idx, datain: pack(l.ce) });
        if (l.isFirst) begin
            for (Integer g = 0; g < 8; g = g + 1)
                if (l.bank[5:3] == fromInteger(g))
                    insGrpQ[g].enq(tuple3(l.bank[2:0], l.subKey, l.idx));
            pendInsertQ.enq(tagged Valid l.bank);
        end else begin
            pendInsertQ.enq(tagged Invalid);
        end
    endrule

    for (Integer g = 0; g < 8; g = g + 1)
        rule insertBank;
            match { .lo, .k, .v } = insGrpQ[g].first; insGrpQ[g].deq;
            for (Integer j = 0; j < 8; j = j + 1)
                if (lo == fromInteger(j)) banks[g * 8 + j].insert(k, v);
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
        loadQ.enq(LoadReq {
            bank: bankOf(gram), subKey: subKeyOf(gram, info.nextGramKey), idx: idx,
            ce: ChainEntry { info: info, isLast: isLast, pad: 0 }, isFirst: isFirst });
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
    method Bool bloomBusy = bloomReqQ.notEmpty || hashInV || hashProdV[0] || hashProdV[1]
                         || hashProdV[2] || hashProdV[3] || hashOutQ.notEmpty
                         || bloomPrQ.notEmpty || verdictQ.notEmpty
                         || passVecQ.notEmpty || passUnpacking || rejectQ.notEmpty;

    method Bool idle;
        Bool grpQueuesEmpty = True;
        for (Integer g = 0; g < 8; g = g + 1)
            grpQueuesEmpty = grpQueuesEmpty && !lkGrpQ[g].notEmpty && !insGrpQ[g].notEmpty;
        Bool allBanksIdle = True;
        for (Integer i = 0; i < valueOf(NHtBanks); i = i + 1)
            allBanksIdle = allBanksIdle && banks[i].notBusy;
        return allBanksIdle && !ctxQ.notEmpty && !outQ.notEmpty
                            && !pendBankQ.notEmpty && !pendInsertQ.notEmpty
                            && !chainBusy
                            && !bloomReqQ.notEmpty && !bloomPrQ.notEmpty
                            && !passVecQ.notEmpty && !passUnpacking
                            && !rejectQ.notEmpty
                            && !loadQ.notEmpty && !dispQ.notEmpty
                            && !hashInV && !hashProdV[0] && !hashProdV[1]
                            && !hashProdV[2] && !hashProdV[3]
                            && !hashOutQ.notEmpty && !verdictQ.notEmpty
                            && !lkRespQ.notEmpty && !chainOutQ.notEmpty
                            && grpQueuesEmpty;
    endmethod
endmodule

endpackage
