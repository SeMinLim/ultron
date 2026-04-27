package GramMatcher;

import CuckooHash::*;
import FIFO::*;
import FIFOF::*;
import Vector::*;

// 64-bank cuckoo hash table — mirrors c_ref/mky_backup/match.c HT_BANKS=64.
//
// 18-bit gram key splits into:
//   bank   = key[5:0]      (low 6 bits)              -> selects one of 64 banks
//   subkey = key[17:6]     (high 12 bits)            -> stored inside the bank
//
// Banking trades a single big cuckoo for 64 small ones.  Storage is the same
// or smaller (each bank holds ~500/64 ≈ 8 keys; sized to 64 slots per table
// per bank for headroom), and we keep a clean path to multi-lane parallel
// lookups in the future (one lookup per bank per cycle).  Today the public
// interface is still single-lane: every lookupReq routes to one bank, and a
// FIFO of pending bank ids tells the response rule which bank's lookupResp
// to pull next so order is preserved.
typedef 64 NHtBanks;

// Width of the per-bank subkey (= 18-bit gram key minus the 6-bit bank id).
typedef 12 SubKeyBits;

typedef struct {
    Bit#(16) ruleId;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
    Bool     stage2;
    Bit#(18) nextGramKey;  // 18-bit gram key (matches c_ref bitmap_idx)
    Bit#(5)  pad;          // keeps total at 64 bits = CuckooHash value width
} RuleInfo deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(16) ruleId;
    Bit#(32) anchor;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
    Bool     stage2;
    Bit#(18) nextGramKey;
} VerifyReq deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) anchor;
    Bit#(32) payLen;
    Bit#(1)  epoch;
    Bit#(6)  pay_off;
    Bool     viable2;
} GramCtx deriving (Bits);

typedef struct {
    VerifyReq vreq;
    Bit#(32)  payLen;
    Bit#(1)   epoch;
    Bit#(6)   pay_off;
    Bool      viable2;
} GramResult deriving (Bits);

interface GramMatcherIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(1) epoch, Bit#(6) pay_off,
                            Bool viable2);
    method ActionValue#(GramResult) lookupResp;
    method Bool idle;
endinterface

(* synthesize *)
module mkGramMatcher(GramMatcherIfc);
    // 64 banks × CuckooHash#(SubKeyBits=12, valSz=64, logSz=5)
    //   logSz=5 → 32 entries per RegFile × 2 tables × 64 banks
    //   = 4096 cuckoo slots total (vs single-bank 32K before).
    //   Per-bank capacity (=64) is ~8× the expected 500/64 load — c_ref's
    //   match_init also sizes per-bank to "max(per_bank*2, 16)" so this is
    //   the same headroom band.
    Vector#(NHtBanks, CuckooHashIfc#(SubKeyBits, 64, 5)) banks
        <- replicateM(mkCuckooHash);

    // Pending bank ids — kept in lookup-issue order.  forwardResult pulls
    // the next response from the bank named at the head of this queue.
    FIFOF#(Bit#(6))    pendBankQ <- mkSizedFIFOF(64);
    FIFOF#(GramCtx)    ctxQ      <- mkSizedFIFOF(64);
    FIFOF#(GramResult) outQ      <- mkSizedFIFOF(64);

    // Insert is also bank-routed.  DataLoader calls insertAck after every
    // insert, so we forward the chosen bank's ack one at a time.  Track
    // which bank fired the latest insert so insertAck pulls from the same.
    FIFOF#(Bit#(6)) pendInsertBankQ <- mkSizedFIFOF(8);
    FIFOF#(Bool)    ackQ            <- mkSizedFIFOF(8);

    function Bit#(6) bankOf(Bit#(32) key)   = key[5:0];
    function Bit#(SubKeyBits) subKeyOf(Bit#(32) key) = key[17:6];

    rule forwardResult (pendBankQ.notEmpty && ctxQ.notEmpty);
        let bank = pendBankQ.first;
        let v <- banks[bank].lookupResp;
        pendBankQ.deq;
        let ctx = ctxQ.first; ctxQ.deq;
        case (v) matches
            tagged Valid .b: begin
                RuleInfo info = unpack(b);
                outQ.enq(GramResult {
                    vreq: VerifyReq {
                        ruleId:      info.ruleId, anchor:      ctx.anchor,
                        pre:         info.pre,    post:        info.post,
                        len:         info.len,
                        stage2:      info.stage2,
                        nextGramKey: info.nextGramKey },
                    payLen:  ctx.payLen,
                    epoch:   ctx.epoch,
                    pay_off: ctx.pay_off,
                    viable2: ctx.viable2 });
            end
            tagged Invalid: noAction;
        endcase
    endrule

    rule forwardInsertAck (pendInsertBankQ.notEmpty);
        let bank = pendInsertBankQ.first; pendInsertBankQ.deq;
        let ok <- banks[bank].insertAck;
        ackQ.enq(ok);
    endrule

    method Action insert(Bit#(32) gram, RuleInfo info);
        let bank = bankOf(gram);
        banks[bank].insert(zeroExtend(subKeyOf(gram)), pack(info));
        pendInsertBankQ.enq(bank);
    endmethod

    method ActionValue#(Bool) insertAck;
        let v = ackQ.first; ackQ.deq; return v;
    endmethod

    method Action lookupReq(Bit#(32) gram, Bit#(32) anchor,
                            Bit#(32) payLen, Bit#(1) epoch, Bit#(6) pay_off,
                            Bool viable2);
        let bank = bankOf(gram);
        banks[bank].lookupReq(zeroExtend(subKeyOf(gram)));
        pendBankQ.enq(bank);
        ctxQ.enq(GramCtx { anchor: anchor, payLen: payLen,
                            epoch: epoch, pay_off: pay_off,
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
                            && !pendBankQ.notEmpty && !pendInsertBankQ.notEmpty;
    endmethod
endmodule

endpackage
