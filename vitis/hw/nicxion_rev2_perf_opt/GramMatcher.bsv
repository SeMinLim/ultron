package GramMatcher;

import BRAM::*;
import BRAMCore::*;
import CuckooHash::*;
import FIFO::*;
import FIFOF::*;
import Vector::*;
import Types::*;
import BloomFilter::*;

typedef 64 NHtBanks;

typedef 30 SubKeyBits;

typedef 13 ChainIdxBits;
typedef 10 ChainLenBits;
typedef TAdd#(ChainLenBits, ChainIdxBits) CuckooValBits;
typedef 8192 NChainEntries;

typedef struct {
    Bit#(16) ruleId;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
    Bool     stage2;
    GramKey nextGramKey;
    AnchorGram anchorGram;
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
    GramKey nextGramKey;
    GramKey pktNextGramKey;
    AnchorGram anchorGram;
    AnchorGram pktAnchorGram;
} VerifyReq deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) anchor;
    Epoch epoch;
    AnchorGram pktAnchorGram;
    GramKey pktNextGramKey;
} GramCtx deriving (Bits);

typedef struct {
    Bool      hit;
    VerifyReq vreq;
    Epoch epoch;
    Bool      lastInChain;
} GramResult deriving (Bits);

typedef struct {
    Bit#(6)             bank;
    Bit#(SubKeyBits)    subKey;
    Bit#(ChainIdxBits)  idx;
    ChainEntry          ce;
    Bool                isFirst;
    Bool                isLast;
} LoadReq deriving (Bits);

typedef struct {
    Bit#(3)            bankLo;
    Bit#(SubKeyBits)   subKey;
    Bit#(CuckooValBits) val;     // {chain length, first chain index}
} InsReq deriving (Bits);

typedef struct {
    GramCtx            ctx;
    Bit#(ChainIdxBits) idx;
    Bool               checkTail;
} ChainRead deriving (Bits);

typedef struct {
    Bit#(6)             bank;
    Bit#(SubKeyBits)    subKey;
    GramCtx             ctx;
} DispReq deriving (Bits);

interface GramMatcherIfc;
    method Action loadEntry(Bit#(32) gram, Bit#(ChainIdxBits) idx,
                            RuleInfo info, Bool isFirst, Bool isLast);
    method ActionValue#(Bool) insertAck;
    method Bool lookupReady;
    method Action lookupReq4(BloomReq4 reqs);
    method ActionValue#(GramResult) lookupResp;
    method ActionValue#(BloomRejectInfo) getReject;
    method Action writeBloom(Bit#(12) addr, Bit#(64) data);
endinterface

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    Vector#(NHtBanks, CuckooHashIfc#(SubKeyBits, CuckooValBits, 9)) banks
        <- replicateM(mkCuckooHash);

    BRAM_Configure cfgAssigns = defaultValue;
    cfgAssigns.memorySize = valueOf(NChainEntries);
    cfgAssigns.latency    = 2;
    BRAM2Port#(Bit#(ChainIdxBits), Bit#(96)) assignsTbl <- mkBRAM2Server(cfgAssigns);

    FIFOF#(Bit#(6))    pendBankQ <- mkSizedFIFOF(64);
    FIFOF#(GramCtx)    ctxQ      <- mkSizedFIFOF(64);
    FIFOF#(GramResult) outQ      <- mkSizedFIFOF(64);

    BloomFilterIfc bloomF <- mkBloomFilter;
    Reg#(BloomPass4) passCur <- mkReg(replicate(tagged Invalid));   // lanes still to send

    FIFOF#(Maybe#(Bit#(6))) pendInsertQ <- mkSizedFIFOF(8);
    FIFOF#(Bool)            ackQ        <- mkSizedFIFOF(8);

    FIFOF#(LoadReq)  loadQ <- mkFIFOF;
    FIFOF#(DispReq)  dispQ <- mkFIFOF;

    Vector#(8, FIFOF#(Tuple2#(Bit#(3), Bit#(SubKeyBits))))
        lkGrpQ  <- replicateM(mkFIFOF);
    Vector#(8, FIFOF#(InsReq))  insGrpQ <- replicateM(mkFIFOF);
    FIFOF#(Tuple2#(Maybe#(Bit#(CuckooValBits)), GramCtx)) lkRespQ <- mkFIFOF;
    FIFOF#(Tuple2#(ChainEntry, GramCtx)) chainOutQ <- mkFIFOF;
    FIFOF#(Epoch)                        missQ     <- mkFIFOF;

    Reg#(Bool)                walking  <- mkReg(False);
    Reg#(Bit#(ChainIdxBits))  walkIdx  <- mkRegU;
    Reg#(Bit#(ChainLenBits))  walkLeft <- mkRegU;
    Reg#(GramCtx)             walkCtx  <- mkRegU;
    Reg#(Bool)                walkSat  <- mkRegU;   // chain length saturated (>= 1023)
    FIFOF#(ChainRead)         chainCtxQ <- mkSizedFIFOF(4);
    FIFOF#(ChainRead)         tailQ    <- mkFIFOF;
    Reg#(Bool)                longSet  <- mkReg(False);
    Reg#(Bool)                longClr  <- mkReg(False);
    Bool longActive = longSet != longClr;

    Reg#(Bit#(6))             headBank   <- mkRegU;
    Reg#(Bit#(SubKeyBits))    headSubKey <- mkRegU;
    Reg#(Bit#(ChainIdxBits))  headIdx    <- mkRegU;
    Reg#(Bit#(ChainLenBits))  headLen    <- mkRegU;
    Bit#(ChainLenBits)        maxLen     = maxBound;

    function Bit#(18) mix18(Bit#(18) k);
        Bit#(18) x = k ^ (k >> 6);
        x = x ^ (x >> 7);
        x = x ^ (x << 11);
        return x;
    endfunction
    function Bit#(6) bankOf(Bit#(32) key) = mix18(key[17:0])[5:0];
    function Bit#(SubKeyBits) subKeyOf(Bit#(32) g0, GramKey g1);
        return { mix18(g0[17:0])[17:6], g1 };
    endfunction

    rule passDrain;
        BloomPass4       rest = passCur;
        Maybe#(BloomCtx) sel  = tagged Invalid;
        for (Integer ln = valueOf(NBloomLanes) - 1; ln >= 0; ln = ln - 1)
            if (isValid(passCur[ln])) sel = passCur[ln];
        Bool found = False;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            if (!found && isValid(passCur[ln])) begin rest[ln] = tagged Invalid; found = True; end
        if (sel matches tagged Valid .ctxv)
            dispQ.enq(DispReq {
                bank:   bankOf(ctxv.gram),
                subKey: subKeyOf(ctxv.gram, ctxv.pktNextGramKey),
                ctx: GramCtx {
                    anchor: ctxv.anchor,
                    epoch: ctxv.epoch,
                    pktAnchorGram: ctxv.pktAnchorGram,
                    pktNextGramKey: ctxv.pktNextGramKey } });
        Bool restEmpty = True;
        for (Integer ln = 0; ln < valueOf(NBloomLanes); ln = ln + 1)
            if (isValid(rest[ln])) restEmpty = False;
        if (restEmpty && bloomF.passReady) begin
            let pv <- bloomF.pass;
            passCur <= pv;
        end else
            passCur <= rest;
    endrule

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

    rule collectLookup;
        let bank = pendBankQ.first; pendBankQ.deq;
        let v <- banks[bank].lookupResp;
        let ctx = ctxQ.first; ctxQ.deq;
        lkRespQ.enq(tuple2(v, ctx));
    endrule

    function Action readChain(Bit#(ChainIdxBits) idx, GramCtx ctx, Bool checkTail);
        action
            assignsTbl.portB.request.put(BRAMRequest {
                write: False, responseOnWrite: False, address: idx, datain: ? });
            chainCtxQ.enq(ChainRead { ctx: ctx, idx: idx, checkTail: checkTail });
        endaction
    endfunction

    rule cuckooLookupResp (!walking && !longActive);
        match { .v, .ctx } = lkRespQ.first; lkRespQ.deq;
        case (v) matches
            tagged Valid .b: begin
                Bit#(ChainLenBits) len = truncateLSB(b);
                Bit#(ChainIdxBits) idx = truncate(b);
                Bool sat = (len == maxLen);
                readChain(idx, ctx, False);          // len >= 1; saturated means len > 1
                if (len > 1) begin
                    walking  <= True;
                    walkIdx  <= idx + 1;
                    walkLeft <= len - 1;
                    walkCtx  <= ctx;
                    walkSat  <= sat;
                end
                if (sat) longSet <= !longSet;
            end
            tagged Invalid: missQ.enq(ctx.epoch);
        endcase
    endrule

    rule chainIssue (walking);
        readChain(walkIdx, walkCtx, walkSat && walkLeft == 1);
        walkIdx  <= walkIdx + 1;
        walkLeft <= walkLeft - 1;
        if (walkLeft == 1) walking <= False;
    endrule

    // Saturated-chain tail: one read per entry until isLast, only while longActive.
    (* descending_urgency = "tailIssue, chainIssue, cuckooLookupResp" *)
    rule tailIssue;
        let r = tailQ.first; tailQ.deq;
        readChain(r.idx, r.ctx, True);
    endrule

    rule chainCollect;
        let raw <- assignsTbl.portB.response.get;
        let r = chainCtxQ.first; chainCtxQ.deq;
        ChainEntry ce = unpack(raw);
        chainOutQ.enq(tuple2(ce, r.ctx));
        if (r.checkTail) begin
            if (ce.isLast) longClr <= !longClr;
            else           tailQ.enq(ChainRead { ctx: r.ctx, idx: r.idx + 1, checkTail: True });
        end
    endrule

    // emitChain (chain entries) and emitMiss share outQ; chain entries go first.
    (* descending_urgency = "emitChain, emitMiss" *)
    rule emitMiss;
        let e = missQ.first; missQ.deq;
        outQ.enq(GramResult { hit: False, vreq: unpack(0), epoch: e, lastInChain: True });
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
            epoch:   cc.epoch,
            lastInChain: ce.isLast });
    endrule

    rule writeChainEntry;
        let l = loadQ.first; loadQ.deq;
        assignsTbl.portA.request.put(BRAMRequest {
            write: True, responseOnWrite: False,
            address: l.idx, datain: pack(l.ce) });
        Bit#(6)            hb  = l.isFirst ? l.bank   : headBank;
        Bit#(SubKeyBits)   hk  = l.isFirst ? l.subKey : headSubKey;
        Bit#(ChainIdxBits) hi  = l.isFirst ? l.idx    : headIdx;
        Bit#(ChainLenBits) len = l.isFirst ? 1        : (headLen == maxLen ? maxLen : headLen + 1);
        if (l.isLast) begin
            for (Integer g = 0; g < 8; g = g + 1)
                if (hb[5:3] == fromInteger(g))
                    insGrpQ[g].enq(InsReq { bankLo: hb[2:0], subKey: hk, val: {len, hi} });
            pendInsertQ.enq(tagged Valid hb);
        end else begin
            headBank   <= hb;
            headSubKey <= hk;
            headIdx    <= hi;
            headLen    <= len;
            pendInsertQ.enq(tagged Invalid);
        end
    endrule

    for (Integer g = 0; g < 8; g = g + 1)
        rule insertBank;
            let r = insGrpQ[g].first; insGrpQ[g].deq;
            for (Integer j = 0; j < 8; j = j + 1)
                if (r.bankLo == fromInteger(j)) banks[g * 8 + j].insert(r.subKey, r.val);
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
            ce: ChainEntry { info: info, isLast: isLast, pad: 0 }, isFirst: isFirst, isLast: isLast });
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
