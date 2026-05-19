package GramMatcher;

import BRAM::*;
import CuckooHash::*;
import FIFO::*;
import FIFOF::*;
import Vector::*;

// 64-bank cuckoo table; value is the base index into the sorted AssignsTable.
typedef 64 NHtBanks;

typedef 12 SubKeyBits;

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
    // 512 entries per table x 2 tables x 64 banks = 65536 slots.
    Vector#(NHtBanks, CuckooHashIfc#(SubKeyBits, ChainIdxBits, 9)) banks
        <- replicateM(mkCuckooHash);

    BRAM_Configure cfgAssigns = defaultValue;
    cfgAssigns.memorySize = valueOf(NChainEntries);
    cfgAssigns.latency    = 1;
    BRAM2Port#(Bit#(ChainIdxBits), Bit#(96)) assignsTbl <- mkBRAM2Server(cfgAssigns);

    FIFOF#(Bit#(6))    pendBankQ <- mkSizedFIFOF(64);
    FIFOF#(GramCtx)    ctxQ      <- mkSizedFIFOF(64);
    FIFOF#(GramResult) outQ      <- mkSizedFIFOF(64);

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
    function Bit#(6) bankOf(Bit#(32) key)            = mix18(key[17:0])[5:0];
    function Bit#(SubKeyBits) subKeyOf(Bit#(32) key) = mix18(key[17:0])[17:6];

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
                    lastInChain: True });
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
            lastInChain: ce.isLast });
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
