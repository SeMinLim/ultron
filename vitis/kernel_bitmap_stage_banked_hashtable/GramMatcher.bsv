package GramMatcher;

import BRAM::*;
import CuckooHash::*;
import FIFO::*;
import FIFOF::*;
import Vector::*;

// 18-bit gram key splits into:
//   bank   = key[5:0]   (low 6 bits)   -> selects one of 64 banks
//   subkey = key[17:6]  (high 12 bits) -> stored inside the bank
typedef 64 NHtBanks;

typedef 12 SubKeyBits;

typedef 16 ChainIdxBits;
typedef 65536 NChainEntries;

// AssignsTable banked 4 ways by idx[1:0]: the chain walk reads four
// consecutive entries per cycle.
typedef 4  NChainBanks;
typedef 14 ChainBankIdxBits;

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
} GramResult deriving (Bits);

interface GramMatcherIfc;
    method Action loadEntry(Bit#(32) gram, Bit#(ChainIdxBits) idx,
                            RuleInfo info, Bool isFirst, Bool isLast);
    method ActionValue#(Bool) insertAck;
    method Action lookupReq(Bit#(32) gram, Bit#(24) pktAnchorGram,
                            Bit#(18) pktNextGramKey, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(3) epoch, Bit#(6) pay_off,
                            Bool viable2);
    method ActionValue#(GramResult) lookupResp;
    method Bool idle;
endinterface

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    Vector#(NHtBanks, CuckooHashIfc#(SubKeyBits, ChainIdxBits, 9)) banks
        <- replicateM(mkCuckooHash);

    // AssignsTable in 4 banks: entries base..base+3 land in 4 different banks.
    BRAM_Configure cfgAssigns = defaultValue;
    cfgAssigns.memorySize = valueOf(NChainEntries) / valueOf(NChainBanks);
    cfgAssigns.latency    = 1;
    Vector#(NChainBanks, BRAM2Port#(Bit#(ChainBankIdxBits), Bit#(96))) abank
        <- replicateM(mkBRAM2Server(cfgAssigns));

    FIFOF#(Bit#(6))    pendBankQ <- mkSizedFIFOF(64);
    FIFOF#(GramCtx)    ctxQ      <- mkSizedFIFOF(64);
    FIFOF#(GramResult) outQ      <- mkSizedFIFOF(64);

    FIFOF#(Maybe#(Bit#(6))) pendInsertQ <- mkSizedFIFOF(8);
    FIFOF#(Bool)            ackQ        <- mkSizedFIFOF(8);

    // Chain-follow state.  A "group" is the 4 entries at one bank row.
    Reg#(Bool)                   chainBusy  <- mkReg(False);
    Reg#(Bit#(ChainBankIdxBits)) chainRow   <- mkRegU;
    Reg#(Bit#(2))                chainStart <- mkRegU;
    Reg#(Bool)                   chainFirst <- mkRegU;
    Reg#(GramCtx)                chainCtx   <- mkRegU;
    // Rare path: a group with >1 match emits one match/cycle from grpReg.
    Reg#(Vector#(4, ChainEntry)) grpReg     <- mkRegU;
    Reg#(Bit#(4))                drainMask  <- mkReg(0);
    Reg#(Bool)                   drainLast  <- mkRegU;

    function Bit#(18) mix18(Bit#(18) k);
        Bit#(18) x = k ^ (k >> 6);
        x = x ^ (x >> 7);
        x = x ^ (x << 11);
        return x;
    endfunction
    function Bit#(6) bankOf(Bit#(32) key)            = mix18(key[17:0])[5:0];
    function Bit#(SubKeyBits) subKeyOf(Bit#(32) key) = mix18(key[17:0])[17:6];

    function Bit#(2) lowLane(Bit#(4) m);
        return (m[0] == 1) ? 0 : (m[1] == 1) ? 1 : (m[2] == 1) ? 2 : 3;
    endfunction

    function GramResult mkHit(ChainEntry ce, GramCtx ctx, Bool last);
        return GramResult {
            hit: True,
            vreq: VerifyReq {
                ruleId:         ce.info.ruleId,
                anchor:         ctx.anchor,
                pre:            ce.info.pre,
                post:           ce.info.post,
                len:            ce.info.len,
                stage2:         ce.info.stage2,
                nextGramKey:    ce.info.nextGramKey,
                pktNextGramKey: ctx.pktNextGramKey,
                anchorGram:     ce.info.anchorGram,
                pktAnchorGram:  ctx.pktAnchorGram },
            payLen:  ctx.payLen,
            epoch:   ctx.epoch,
            pay_off: ctx.pay_off,
            viable2: ctx.viable2,
            lastInChain: last };
    endfunction

    function GramResult mkTerm(GramCtx ctx);
        return GramResult {
            hit: False, vreq: unpack(0),
            payLen: ctx.payLen, epoch: ctx.epoch, pay_off: ctx.pay_off,
            viable2: ctx.viable2, lastInChain: True };
    endfunction

    function Action issueGroup(Bit#(ChainBankIdxBits) row);
        action
            for (Integer i = 0; i < valueOf(NChainBanks); i = i + 1)
                abank[i].portB.request.put(BRAMRequest {
                    write: False, responseOnWrite: False,
                    address: row, datain: ? });
        endaction
    endfunction

    rule cuckooLookupResp (!chainBusy && pendBankQ.notEmpty && ctxQ.notEmpty);
        let bank = pendBankQ.first;
        let v <- banks[bank].lookupResp;
        pendBankQ.deq;
        let ctx = ctxQ.first; ctxQ.deq;
        case (v) matches
            tagged Valid .b: begin
                Bit#(ChainIdxBits) idx = unpack(b);
                issueGroup(idx[15:2]);
                chainRow   <= idx[15:2];
                chainStart <= idx[1:0];
                chainFirst <= True;
                chainCtx   <= ctx;
                chainBusy  <= True;
            end
            tagged Invalid:
                outQ.enq(mkTerm(ctx));
        endcase
    endrule

    // Consume one 4-entry group, emit every in-chain entry (no filtering --
    // banking transform only).  The 4 entries spill out at 1/cycle through
    // grpReg + drainMask so outQ keeps its 1-entry-per-cycle contract.
    rule chainRead (chainBusy && drainMask == 0);
        let r0 <- abank[0].portB.response.get;
        let r1 <- abank[1].portB.response.get;
        let r2 <- abank[2].portB.response.get;
        let r3 <- abank[3].portB.response.get;
        Vector#(4, ChainEntry) g = cons(unpack(r0), cons(unpack(r1),
                                   cons(unpack(r2), cons(unpack(r3), nil))));

        Bit#(2) startLane = chainFirst ? chainStart : 0;
        Bool s0 = (startLane <= 0);
        Bool s1 = (startLane <= 1);
        Bool s2 = (startLane <= 2);

        Bool l0 = s0 && g[0].isLast;
        Bool l1 = s1 && g[1].isLast;
        Bool l2 = s2 && g[2].isLast;
        Bool l3 =       g[3].isLast;
        Bool hasLast = l0 || l1 || l2 || l3;
        Bit#(2) lastLane = l0 ? 0 : l1 ? 1 : l2 ? 2 : 3;

        // in-chain lanes: at/after the start lane, at/before the isLast lane.
        Bool c0 = s0 && (!hasLast || (lastLane >= 0));
        Bool c1 = s1 && (!hasLast || (lastLane >= 1));
        Bool c2 = s2 && (!hasLast || (lastLane >= 2));
        Bool c3 =       (!hasLast || (lastLane >= 3));
        Bit#(4) mm = {pack(c3), pack(c2), pack(c1), pack(c0)};

        Bit#(2) lane = lowLane(mm);
        Bit#(4) rest = mm & ~(4'b0001 << lane);
        Bool    onlyOne = (rest == 0);

        if (mm == 0) begin
            issueGroup(chainRow + 1);
            chainRow   <= chainRow + 1;
            chainFirst <= False;
        end
        else if (onlyOne) begin
            Bool isFinal = hasLast && (lastLane == lane);
            outQ.enq(mkHit(g[lane], chainCtx, isFinal));
            if (isFinal) begin
                chainBusy <= False;
            end else begin
                issueGroup(chainRow + 1);
                chainRow   <= chainRow + 1;
                chainFirst <= False;
            end
        end
        else begin
            outQ.enq(mkHit(g[lane], chainCtx, False));
            grpReg    <= g;
            drainLast <= hasLast;
            drainMask <= rest;
        end
    endrule

    rule chainDrain (chainBusy && drainMask != 0);
        Bit#(2) lane = lowLane(drainMask);
        Bit#(4) rest = drainMask & ~(4'b0001 << lane);
        Bool isFinal = (rest == 0) && drainLast;
        outQ.enq(mkHit(grpReg[lane], chainCtx, isFinal));
        drainMask <= rest;
        if (rest == 0) begin
            if (drainLast) begin
                chainBusy <= False;
            end else begin
                issueGroup(chainRow + 1);
                chainRow   <= chainRow + 1;
                chainFirst <= False;
            end
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
        abank[idx[1:0]].portA.request.put(BRAMRequest {
            write: True, responseOnWrite: False,
            address: idx[15:2], datain: pack(ce) });
        if (isFirst) begin
            let bank = bankOf(gram);
            banks[bank].insert(zeroExtend(subKeyOf(gram)), idx);
            pendInsertQ.enq(tagged Valid bank);
        end else begin
            pendInsertQ.enq(tagged Invalid);
        end
    endmethod

    method ActionValue#(Bool) insertAck;
        let v = ackQ.first; ackQ.deq; return v;
    endmethod

    method Action lookupReq(Bit#(32) gram, Bit#(24) pktAnchorGram,
                            Bit#(18) pktNextGramKey, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(3) epoch, Bit#(6) pay_off,
                            Bool viable2);
        let bank = bankOf(gram);
        banks[bank].lookupReq(zeroExtend(subKeyOf(gram)));
        pendBankQ.enq(bank);
        ctxQ.enq(GramCtx { anchor: anchor, payLen: payLen,
                            epoch: epoch, pay_off: pay_off,
                            pktAnchorGram: pktAnchorGram,
                            pktNextGramKey: pktNextGramKey,
                            viable2: viable2 });
    endmethod

    method ActionValue#(GramResult) lookupResp;
        let v = outQ.first; outQ.deq; return v;
    endmethod

    method Bool idle;
        Bool allBanksIdle = True;
        for (Integer i = 0; i < valueOf(NHtBanks); i = i + 1)
            allBanksIdle = allBanksIdle && banks[i].notBusy;
        return allBanksIdle && !ctxQ.notEmpty && !outQ.notEmpty
                            && !pendBankQ.notEmpty && !pendInsertQ.notEmpty
                            && !chainBusy;
    endmethod
endmodule

endpackage
