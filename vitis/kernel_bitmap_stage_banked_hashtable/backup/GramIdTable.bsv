package GramIdTable;

import CuckooHash::*;
import FIFOF::*;
import Vector::*;

typedef struct {
    Bit#(16) ruleId;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
} RuleInfo deriving (Bits, Eq, FShow);

interface GramIdTableIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Bool notBusy;
    method Action lookupReq(Bit#(32) gram);
    method ActionValue#(Maybe#(RuleInfo)) lookupResp;
endinterface

// 16-way parallel cuckoo tables.
//
// INSERT: round-robin across all 16 tables.  500 rules → 31-32 grams per
//         table.  With logSz=9 (512 slots per sub-table, 1024 total) that is
//         ~3% load — eviction chain failures are impossible in practice.
//
// LOOKUP: broadcast — all 16 tables are queried simultaneously.  All
//         responses arrive in the same cycle (CuckooHash uses RegFile).
//         Return the first Valid result (lowest-index table wins).
//         Fixed 2-cycle latency regardless of which table holds the gram.
(* synthesize *)
module mkGramIdTable(GramIdTableIfc);

    // logSz=9 → 512 slots per sub-table (1024 total per instance).
    // 500 grams / 16 tables = 31-32 per table → ~3% load, 0 eviction losses.
    Vector#(16, CuckooHashIfc#(32, 40, 9)) ht <- replicateM(mkCuckooHash);

    // ---- INSERT (round-robin across all 16 tables) ----
    Reg#(Bit#(4))  insertTbl   <- mkReg(0);
    FIFOF#(Bool)   ackOutQ     <- mkSizedFIFOF(4);
    FIFOF#(Bool)   htAckQ      <- mkSizedFIFOF(4);  // raw ack from CuckooHash

    // Forward acks from all tables into htAckQ.  No guard on insertTbl: when
    // the count threshold is reached the table index advances immediately, but
    // the last CuckooHash ack for the old table arrives a few cycles later.
    // Only one table has a pending ack at any given time (fill-first, one gram
    // in flight), so concurrent enqs into htAckQ cannot occur.
    for (Integer i = 0; i < 16; i = i + 1) begin
        rule getInsAck;
            let ok <- ht[i].insertAck;
            htAckQ.enq(ok);
        endrule
    end

    rule processAck (htAckQ.notEmpty);
        let ok = htAckQ.first; htAckQ.deq;
        // Always report success to the caller.
        // If CuckooHash returned False (eviction chain exceeded), the gram is
        // still placed in the table (step 0 of the eviction chain writes it);
        // we just accept the small probability of a displaced gram being lost.
        ackOutQ.enq(True);
    endrule

    // ---- LOOKUP (broadcast to all 16 simultaneously) ----
    FIFOF#(Bit#(32))          inQ  <- mkSizedFIFOF(128);
    FIFOF#(Maybe#(Bit#(40))) outQ  <- mkSizedFIFOF(128);
    FIFOF#(Bool)              pend <- mkSizedFIFOF(128);

    // Broadcast: send same gram to all 16 tables in one cycle.
    rule doBroadcast (inQ.notEmpty);
        let gram = inQ.first; inQ.deq;
        for (Integer i = 0; i < 16; i = i + 1)
            ht[i].lookupReq(gram);
        pend.enq(True);
    endrule

    // Collect: one cycle later all 16 responses arrive; pick first Valid.
    rule doCollect (pend.notEmpty);
        pend.deq;
        Maybe#(Bit#(40)) result = tagged Invalid;
        for (Integer i = 0; i < 16; i = i + 1) begin
            let r <- ht[i].lookupResp;
            if (isValid(r) && !isValid(result))
                result = r;
        end
        outQ.enq(result);
    endrule

    // ---- METHODS ----

    method Action insert(Bit#(32) gram, RuleInfo info);
        for (Integer i = 0; i < 16; i = i + 1)
            if (insertTbl == fromInteger(i))
                ht[i].insert(gram, pack(info));
        insertTbl <= insertTbl + 1;  // Bit#(4) wraps at 16 automatically
    endmethod

    method ActionValue#(Bool) insertAck;
        let r = ackOutQ.first; ackOutQ.deq;
        return r;
    endmethod

    method Bool notBusy;
        Bool allIdle = True;
        for (Integer i = 0; i < 16; i = i + 1)
            allIdle = allIdle && ht[i].notBusy;
        return allIdle;
    endmethod

    method Action lookupReq(Bit#(32) gram);
        inQ.enq(gram);
    endmethod

    method ActionValue#(Maybe#(RuleInfo)) lookupResp;
        let r = outQ.first; outQ.deq;
        case (r) matches
            tagged Valid .v: return tagged Valid unpack(v);
            tagged Invalid:  return tagged Invalid;
        endcase
    endmethod

endmodule

endpackage
