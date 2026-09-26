package GramMatcher;

import BRAM::*;
import BRAMCore::*;
import CuckooHash::*;
import FIFO::*;
import FIFOF::*;
import Vector::*;
import Types::*;
import BloomFilter::*;

// Banked gram matcher for bitmap candidates.
// Cuckoo values point into AssignsTable chains; isLast terminates each chain.
typedef 64 NHtBanks;

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
    Epoch epoch;
    Bit#(24) pktAnchorGram;
    Bit#(18) pktNextGramKey;
    Bool     viable2;
} GramCtx deriving (Bits);

typedef struct {
    Bool      hit;
    VerifyReq vreq;
    Bit#(32)  payLen;
    Epoch epoch;
    Bool      viable2;
    Bool      lastInChain;
    Bool      bloomReject;   // True only for results killed by the bloom pre-filter
} GramResult deriving (Bits);

// A DB-load entry, queued so loadEntry's ready signal is one local FIFO flag
// (bank index and subkey are computed on the way in).
typedef struct {
    Bit#(6)             bank;
    Bit#(SubKeyBits)    subKey;
    Bit#(ChainIdxBits)  idx;
    ChainEntry          ce;
    Bool                isFirst;
} LoadReq deriving (Bits);

// A cuckoo insert routed to its bank group (low 3 bits pick the bank in it).
typedef struct {
    Bit#(3)            bankLo;
    Bit#(SubKeyBits)   subKey;
    Bit#(ChainIdxBits) idx;
} InsReq deriving (Bits);

// A cuckoo lookup whose bank is already decided, one register stage ahead of
// the 64-way bank dispatch.
typedef struct {
    Bit#(6)             bank;
    Bit#(SubKeyBits)    subKey;
    GramCtx             ctx;
} DispReq deriving (Bits);

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
endinterface

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
    cfgAssigns.latency    = 2;
    BRAM2Port#(Bit#(ChainIdxBits), Bit#(96)) assignsTbl <- mkBRAM2Server(cfgAssigns);

    FIFOF#(Bit#(6))    pendBankQ <- mkSizedFIFOF(64);
    FIFOF#(GramCtx)    ctxQ      <- mkSizedFIFOF(64);
    FIFOF#(GramResult) outQ      <- mkSizedFIFOF(64);

    // Bloom pre-filter (BloomFilter.bsv).  Passing lanes (rare) are unpacked
    // here 1/cycle into the cuckoo backend; rejects go straight to getReject.
    BloomFilterIfc bloomF <- mkBloomFilter;
    Reg#(Bit#(3))    passUnpackIdx <- mkReg(0);
    Reg#(Bool)       passUnpacking <- mkReg(False);
    Reg#(BloomPass4) passCur       <- mkRegU;

    // pendInsertQ preserves load-side ack ordering across banked and non-first entries.
    FIFOF#(Maybe#(Bit#(6))) pendInsertQ <- mkSizedFIFOF(8);
    FIFOF#(Bool)            ackQ        <- mkSizedFIFOF(8);

    FIFOF#(LoadReq)  loadQ <- mkFIFOF;
    FIFOF#(DispReq)  dispQ <- mkFIFOF;

    Vector#(8, FIFOF#(Tuple2#(Bit#(3), Bit#(SubKeyBits))))
        lkGrpQ  <- replicateM(mkFIFOF);
    Vector#(8, FIFOF#(InsReq))  insGrpQ <- replicateM(mkFIFOF);
    // Cuckoo response, registered before the chain/miss decision.
    FIFOF#(Tuple2#(Maybe#(Bit#(ChainIdxBits)), GramCtx)) lkRespQ <- mkFIFOF;
    // Chain entries, registered before they are formatted into outQ.
    FIFOF#(Tuple2#(ChainEntry, GramCtx)) chainOutQ <- mkFIFOF;

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

    // Drain one pass-vector across cycles into the 1-wide cuckoo backend.
    rule passLoad (!passUnpacking);
        let pv <- bloomF.pass;
        passCur       <= pv;
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
                    epoch: ctxv.epoch,
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
                    viable2: ctx.viable2,
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

    // cuckooLookupResp (misses) and emitChain (chain entries) share outQ.
    // A miss is one beat and never stalls the chain for more than a cycle.
    (* descending_urgency = "cuckooLookupResp, emitChain" *)
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
                    insGrpQ[g].enq(InsReq { bankLo: l.bank[2:0], subKey: l.subKey, idx: l.idx });
            pendInsertQ.enq(tagged Valid l.bank);
        end else begin
            pendInsertQ.enq(tagged Invalid);
        end
    endrule

    for (Integer g = 0; g < 8; g = g + 1)
        rule insertBank;
            let r = insGrpQ[g].first; insGrpQ[g].deq;
            for (Integer j = 0; j < 8; j = j + 1)
                if (r.bankLo == fromInteger(j)) banks[g * 8 + j].insert(r.subKey, r.idx);
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

    method Bool lookupReady = bloomF.reqReady;

    method Action lookupReq4(BloomReq4 reqs);
        bloomF.req(reqs);
    endmethod

    method ActionValue#(GramResult) lookupResp;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method ActionValue#(BloomRejectInfo) getReject = bloomF.reject;

    method Action writeBloom(Bit#(12) addr, Bit#(64) data);
        bloomF.write(addr, data);
    endmethod

endmodule

endpackage
