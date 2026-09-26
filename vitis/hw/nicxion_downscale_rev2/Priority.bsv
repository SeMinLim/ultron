package Priority;

import BRAM::*;
import FIFOF::*;
import Vector::*;
import Types::*;

typedef NEpoch PriorityEpochCount;   // one slot per kernel epoch (Types)
typedef Epoch  PriorityEpoch;

typedef struct {
    PriorityEpoch epoch;
    Bit#(32)      pktIdx;
    Bool          hit;
    Bit#(16)      ruleId;
} PriorityCandidate deriving (Bits, Eq, FShow);

typedef struct {
    PriorityEpoch epoch;
    Bit#(32)      pktIdx;
} PriorityFinish deriving (Bits, Eq, FShow);

typedef struct {
    PriorityEpoch epoch;
    Bit#(32)      pktIdx;
    Bool          hit;
    Bit#(16)      ruleId;
    Bit#(2)       prio;
} PriorityResult deriving (Bits, Eq, FShow);

interface PriorityIfc;
    method Action putCandidate(PriorityCandidate candidate);
    method Action finishEpoch(PriorityEpoch epoch, Bit#(32) pktIdx);
    method ActionValue#(PriorityResult) getResult;


    method Action writePriority(Bit#(16) ruleId, Bit#(2) prio);
endinterface

(* synthesize *)
module mkPriority(PriorityIfc);

    BRAM_Configure cfg = defaultValue;
    cfg.memorySize   = 8192;
    cfg.outFIFODepth = 2;
    BRAM2Port#(Bit#(16), Bit#(2)) priorityTable <- mkBRAM2Server(cfg);

    FIFOF#(PriorityCandidate) lookupQ <- mkSizedFIFOF(32);
    FIFOF#(PriorityFinish)    finishQ <- mkSizedFIFOF(16);
    FIFOF#(PriorityResult)    outQ    <- mkSizedFIFOF(16);

    Vector#(PriorityEpochCount, Reg#(Bool))     bestHit      <- replicateM(mkReg(False));
    Vector#(PriorityEpochCount, Reg#(Bit#(16))) bestRuleId   <- replicateM(mkRegU);
    Vector#(PriorityEpochCount, Reg#(Bit#(2)))  bestPriority <- replicateM(mkRegU);
    Vector#(PriorityEpochCount, Reg#(Bit#(16))) inFlight     <- replicateM(mkReg(0));
    RWire#(PriorityEpoch) incrEpoch <- mkRWire;
    RWire#(PriorityEpoch) decrEpoch <- mkRWire;

    function Bool maybeEpochEq(Maybe#(PriorityEpoch) m, PriorityEpoch e);
        Bool eq = False;
        case (m) matches
            tagged Valid .x: eq = (x == e);
            tagged Invalid:  eq = False;
        endcase
        return eq;
    endfunction

    function Bit#(16) applyDelta(Bit#(16) cur, Bool inc, Bool dec);
        Bit#(16) next = cur;
        if (inc && !dec)
            next = cur + 1;
        else if (!inc && dec)
            next = cur - 1;
        return next;
    endfunction

    for (Integer i = 0; i < valueOf(PriorityEpochCount); i = i + 1) begin
        PriorityEpoch e = fromInteger(i);
        rule updateInFlight(maybeEpochEq(incrEpoch.wget, e) || maybeEpochEq(decrEpoch.wget, e));
            inFlight[i] <= applyDelta(inFlight[i], maybeEpochEq(incrEpoch.wget, e),
                                                   maybeEpochEq(decrEpoch.wget, e));
        endrule
    end

    rule collectLookup;
        let c = lookupQ.first; lookupQ.deq;
        let p <- priorityTable.portA.response.get();

        decrEpoch.wset(c.epoch);
        if (c.hit && ((!bestHit[c.epoch]) || (p > bestPriority[c.epoch])
                      || (p == bestPriority[c.epoch] && c.ruleId < bestRuleId[c.epoch]))) begin
            bestHit[c.epoch]      <= True;
            bestRuleId[c.epoch]   <= c.ruleId;
            bestPriority[c.epoch] <= p;
        end
    endrule

    // collectLookup updates one epoch's best-so-far; emitFinished reads and
    // clears another's.  bsc sees the shared bestHit vector and keeps them
    // apart.  They never touch the same epoch in one cycle (emitFinished waits
    // for inFlight == 0), so the order only decides who waits a cycle:
    // finishing first frees the epoch sooner.
    (* descending_urgency = "emitFinished, collectLookup" *)
    // Legal once every candidate for this epoch has been looked up.
    rule emitFinished(inFlight[finishQ.first.epoch] == 0);
        let f = finishQ.first; finishQ.deq;
        let e = f.epoch;
        outQ.enq(PriorityResult {
            epoch:    e,
            pktIdx:   f.pktIdx,
            hit:      bestHit[e],
            ruleId:   bestHit[e] ? bestRuleId[e] : 0,
            prio:     bestHit[e] ? bestPriority[e] : 0
        });
        bestHit[e]      <= False;   // bestRuleId/bestPriority are only read while bestHit
    endrule

    method Action putCandidate(PriorityCandidate candidate);
        priorityTable.portA.request.put(BRAMRequest {
            write: False,
            responseOnWrite: False,
            address: candidate.ruleId,
            datain: ?
        });
        lookupQ.enq(candidate);
        incrEpoch.wset(candidate.epoch);
    endmethod

    method Action finishEpoch(PriorityEpoch epoch, Bit#(32) pktIdx);
        finishQ.enq(PriorityFinish { epoch: epoch, pktIdx: pktIdx });
    endmethod

    method ActionValue#(PriorityResult) getResult;
        let r = outQ.first; outQ.deq; return r;
    endmethod


    method Action writePriority(Bit#(16) ruleId, Bit#(2) prio);
        priorityTable.portB.request.put(BRAMRequest {
            write: True,
            responseOnWrite: False,
            address: ruleId,
            datain: prio
        });
    endmethod

endmodule

endpackage
