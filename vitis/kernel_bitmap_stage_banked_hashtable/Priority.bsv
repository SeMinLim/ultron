package Priority;

import BRAM::*;
import FIFOF::*;
import Vector::*;

typedef 8 PriorityEpochCount;
typedef Bit#(3) PriorityEpoch;

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

    method Bool inputReady;
    method Bool outputReady;
    method Bool idle;

    method Action writePriority(Bit#(16) ruleId, Bit#(2) prio);
endinterface

(* synthesize *)
module mkPriority(PriorityIfc);

    BRAM_Configure cfg = defaultValue;
    cfg.memorySize   = 65536;
    cfg.outFIFODepth = 2;
    BRAM2Port#(Bit#(16), Bit#(2)) priorityTable <- mkBRAM2Server(cfg);

    FIFOF#(PriorityCandidate) lookupQ <- mkSizedFIFOF(32);
    FIFOF#(PriorityFinish)    finishQ <- mkSizedFIFOF(16);
    FIFOF#(PriorityResult)    outQ    <- mkSizedFIFOF(16);

    Vector#(PriorityEpochCount, Reg#(Bool))     bestHit      <- replicateM(mkReg(False));
    Vector#(PriorityEpochCount, Reg#(Bit#(16))) bestRuleId   <- replicateM(mkReg(0));
    Vector#(PriorityEpochCount, Reg#(Bit#(2)))  bestPriority <- replicateM(mkReg(0));
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

    rule updateInFlight0(maybeEpochEq(incrEpoch.wget, 0) ||
                         maybeEpochEq(decrEpoch.wget, 0));
        inFlight[0] <= applyDelta(inFlight[0],
                                  maybeEpochEq(incrEpoch.wget, 0),
                                  maybeEpochEq(decrEpoch.wget, 0));
    endrule

    rule updateInFlight1(maybeEpochEq(incrEpoch.wget, 1) ||
                         maybeEpochEq(decrEpoch.wget, 1));
        inFlight[1] <= applyDelta(inFlight[1],
                                  maybeEpochEq(incrEpoch.wget, 1),
                                  maybeEpochEq(decrEpoch.wget, 1));
    endrule

    rule updateInFlight2(maybeEpochEq(incrEpoch.wget, 2) ||
                         maybeEpochEq(decrEpoch.wget, 2));
        inFlight[2] <= applyDelta(inFlight[2],
                                  maybeEpochEq(incrEpoch.wget, 2),
                                  maybeEpochEq(decrEpoch.wget, 2));
    endrule

    rule updateInFlight3(maybeEpochEq(incrEpoch.wget, 3) ||
                         maybeEpochEq(decrEpoch.wget, 3));
        inFlight[3] <= applyDelta(inFlight[3],
                                  maybeEpochEq(incrEpoch.wget, 3),
                                  maybeEpochEq(decrEpoch.wget, 3));
    endrule

    rule updateInFlight4(maybeEpochEq(incrEpoch.wget, 4) ||
                         maybeEpochEq(decrEpoch.wget, 4));
        inFlight[4] <= applyDelta(inFlight[4],
                                  maybeEpochEq(incrEpoch.wget, 4),
                                  maybeEpochEq(decrEpoch.wget, 4));
    endrule

    rule updateInFlight5(maybeEpochEq(incrEpoch.wget, 5) ||
                         maybeEpochEq(decrEpoch.wget, 5));
        inFlight[5] <= applyDelta(inFlight[5],
                                  maybeEpochEq(incrEpoch.wget, 5),
                                  maybeEpochEq(decrEpoch.wget, 5));
    endrule

    rule updateInFlight6(maybeEpochEq(incrEpoch.wget, 6) ||
                         maybeEpochEq(decrEpoch.wget, 6));
        inFlight[6] <= applyDelta(inFlight[6],
                                  maybeEpochEq(incrEpoch.wget, 6),
                                  maybeEpochEq(decrEpoch.wget, 6));
    endrule

    rule updateInFlight7(maybeEpochEq(incrEpoch.wget, 7) ||
                         maybeEpochEq(decrEpoch.wget, 7));
        inFlight[7] <= applyDelta(inFlight[7],
                                  maybeEpochEq(incrEpoch.wget, 7),
                                  maybeEpochEq(decrEpoch.wget, 7));
    endrule

    rule collectLookup(lookupQ.notEmpty);
        let c = lookupQ.first; lookupQ.deq;
        let p <- priorityTable.portA.response.get();

        decrEpoch.wset(c.epoch);
        if (c.hit && ((!bestHit[c.epoch]) || (p > bestPriority[c.epoch]))) begin
            bestHit[c.epoch]      <= True;
            bestRuleId[c.epoch]   <= c.ruleId;
            bestPriority[c.epoch] <= p;
        end
    endrule

    rule emitFinished(finishQ.notEmpty && outQ.notFull &&
                      inFlight[finishQ.first.epoch] == 0);
        let f = finishQ.first; finishQ.deq;
        let e = f.epoch;
        outQ.enq(PriorityResult {
            epoch:    e,
            pktIdx:   f.pktIdx,
            hit:      bestHit[e],
            ruleId:   bestHit[e] ? bestRuleId[e] : 0,
            prio:     bestHit[e] ? bestPriority[e] : 0
        });
        bestHit[e]      <= False;
        bestRuleId[e]   <= 0;
        bestPriority[e] <= 0;
    endrule

    method Action putCandidate(PriorityCandidate candidate) if (lookupQ.notFull);
        priorityTable.portA.request.put(BRAMRequest {
            write: False,
            responseOnWrite: False,
            address: candidate.ruleId,
            datain: ?
        });
        lookupQ.enq(candidate);
        incrEpoch.wset(candidate.epoch);
    endmethod

    method Action finishEpoch(PriorityEpoch epoch, Bit#(32) pktIdx) if (finishQ.notFull);
        finishQ.enq(PriorityFinish { epoch: epoch, pktIdx: pktIdx });
    endmethod

    method ActionValue#(PriorityResult) getResult if (outQ.notEmpty);
        let r = outQ.first; outQ.deq; return r;
    endmethod

    method Bool inputReady  = lookupQ.notFull;
    method Bool outputReady = outQ.notEmpty;
    method Bool idle        = !lookupQ.notEmpty && !finishQ.notEmpty && !outQ.notEmpty;

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
