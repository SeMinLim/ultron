package KernelMain;

import FIFO::*;
import FIFOF::*;
import ConfigReg::*;
import DReg::*;
import Vector::*;

import BitmapUram::*;
import CycleCounter::*;
import ExactPatternTable::*;
import GramMatcher::*;
import BloomFilter::*;
import NgramExtracter::*;
import PacketMeta::*;
import ExactMatch::*;
import PortOffsetMatcher::*;
import Priority::*;
import AxiStream::*;
import DbStreamLoader::*;
import ResultStreamWriter::*;
import PacketStreamReader::*;
import Types::*;

interface KernelMainIfc;
    // Free-running (ap_ctrl_none): no start/done handshake. The kernel boots,
    // loads the rule DB off s_axis_db, then processes packets forever.
    interface AxiStreamSlavePinsIfc#(512) s_axis_db;
    interface AxiStreamSlaveUserPinsIfc#(512, 128) s_axis_pkt;
    interface AxiStreamMasterPinsIfc#(32) m_axis_result;
endinterface

typedef enum { KIdle, KInit, KProcess } KState deriving (Bits, Eq, FShow);

typedef struct {
    Epoch    epoch;
    PktIdx   pktIdx;
} PomCtx deriving (Bits, Eq, FShow);

// n-gram batch waiting for its bitmap results (absorb/flush -> pairBitmapResults).
typedef struct {
    Epoch                                   epoch;
    Vector#(NBitmapLanes, Maybe#(NgramOut)) grams;
    Vector#(NBitmapLanes, Bool)             nextValid;   // lane has a gram 3 bytes on
    Vector#(NBitmapLanes, Bit#(18))         nextKey;     // that gram's bitmap key
} GramSide deriving (Bits);

// Lanes that need a cuckoo lookup (pairBitmapResults -> scan).  Phase A keys
// stage-2 hits with the next gram and stage-1 hits with 0; phase B re-looks-up
// lanes that are both, with key 0.
typedef struct {
    Epoch                                   epoch;
    Vector#(NBitmapLanes, Bool)             needA;
    Vector#(NBitmapLanes, Bool)             needB;
    Vector#(NBitmapLanes, Maybe#(NgramOut)) grams;
    Vector#(NBitmapLanes, Bit#(18))         keyA;
} ScanJob deriving (Bits);

// One scan pass, set up by startScan and drained 4 need-lanes/cycle by doScan.
typedef struct {
    Epoch                              epoch;
    Bool                               last;    // this pass retires the entry
    Vector#(NBitmapLanes, Bool)        sel;     // lane is a real need-lane
    Vector#(NBitmapLanes, Bit#(7))     rank;    // exclusive prefix rank
    Vector#(NBitmapLanes, NgramOut)    gram;    // unwrapped gram per lane
    Vector#(NBitmapLanes, Bit#(18))    bm1K;
    Bit#(7)                            count;   // number of need-lanes
} ScanPass deriving (Bits);

// An exact-match hit on its way to the port/offset stage.
typedef struct {
    Epoch    epoch;
    RuleId   ruleId;
    Bit#(32) matchPos;
    Bit#(32) endOff;
} ExactHit deriving (Bits);

// A hit with its packet metadata captured, before the end-offset check.
typedef struct {
    Epoch      epoch;
    Bit#(32)   endOff;
    PomPktMeta meta;
} PomRelease deriving (Bits);

typedef struct {
    PktIdx   pktIdx;
    Bool     hit;
    RuleId   ruleId;
    Bit#(15) latency;   // E2E: admit->retire cycles (15-bit saturated)
} RetireResult deriving (Bits, Eq, FShow);

module mkKernelMain(KernelMainIfc);

    ExactPatternTableIfc  patternTable <- mkExactPatternTable;
    BitmapUramIfc         bm0_s1       <- mkBitmapUram;
    BitmapUramIfc         bm0_s2       <- mkBitmapUram;
    BitmapUramIfc         bm1          <- mkBitmapUram;
    GramMatcherIfc        gram         <- mkGramMatcher;
    NgramExtracterIfc     ngram        <- mkNgramExtracter;
    PacketMetaIfc         pktMeta      <- mkPacketMeta;
    ExactMatchIfc         exactMatch   <- mkExactMatchParallel(patternTable);
    PortOffsetMatcherIfc  portMatch    <- mkPortOffsetMatcher;
    PriorityIfc           prioStage    <- mkPriority;
    // DB Master->Slave (Req 1): rules are PUSHED in over s_axis_db; DataLoaderCore
    // (via DbStreamLoader) loads the matcher tables exactly as the AXI4 path did.
    AxiStreamSlaveIfc#(512) dbStream <- mkAxiStreamSlave_512;
    DbStreamLoaderIfc     dataLoader   <- mkDbStreamLoader(bm0_s1, bm0_s2, bm1, gram, patternTable, portMatch, prioStage, dbStream);
    // Packet input -> AXI Stream (Req 2/3): payload beats on s_axis_pkt with the
    // 5-tuple in tuser on the tlast beat (final-beat metadata model).
    AxiStreamSlaveUserIfc#(512, 128) pktStream <- mkAxiStreamSlaveUser_512_128;
    PacketStreamReaderIfc pktReader <- mkPacketStreamReader(pktStream);
    // Result -> AXI Stream (Req 3/4): ordered {match,ruleId} emitted on
    // m_axis_result, one beat per packet with tlast=1 (tlast && tvalid sync).
    AxiStreamMasterIfc#(32) resStream <- mkAxiStreamMaster_32;
    ResultStreamWriterIfc resultWriter <- mkResultStreamWriter(resStream);

    CycleCounterIfc timerTotal <- mkCycleCounter;

    Reg#(KState) state  <- mkReg(KIdle);
    Reg#(Bool)   booted <- mkReg(False);

    Reg#(Epoch)     curEpoch     <- mkReg(0);
    Reg#(Bool)      metaReady    <- mkReg(False);

    // Epoch allocation: set toggled at admission (feedBeat), clr at retire, so
    // each register has one writer.  ConfigReg: precomputeAdmit reads them after
    // feedBeat in the schedule (old value plus admitNow).
    Vector#(NEpoch, Reg#(Bool))     epochUseSet   <- replicateM(mkConfigReg(False));
    Vector#(NEpoch, Reg#(Bool))     epochUseClr   <- replicateM(mkConfigReg(False));
    function Bool useDiffers(Reg#(Bool) a, Reg#(Bool) b) = a != b;
    Vector#(NEpoch, Bool)           epochInUse    = zipWith(useDiffers, epochUseSet, epochUseClr);
    Vector#(NEpoch, Reg#(PktIdx))   epochPktIdx    <- replicateM(mkRegU);
    Vector#(NEpoch, Reg#(Bit#(32))) admitCyc       <- replicateM(mkRegU);
`ifdef NX_DEBUG
    Reg#(Bit#(32)) wdLast <- mkReg(0);  // watchdog last-dump cycle
`endif
    // Total process-cycle measurement (no per-packet overlap): span from the
    // first packet admitted to the last packet retired, emitted as a footer beat.
    Reg#(Bool)     procStarted  <- mkReg(False);
    Reg#(Bit#(32)) firstAdmitCyc <- mkRegU;   // set with procStarted
    Reg#(Bit#(32)) lastRetireCyc <- mkRegU;   // read only after a retire (footer)
    Reg#(Bit#(32)) idleCnt       <- mkReg(0);
    Reg#(Bool)     footerDone    <- mkReg(False);
    // admit->now latency for epoch e, saturated to 15 bits.
    function Bit#(15) e2eLatency(Epoch e);
        Bit#(32) d = timerTotal.value - admitCyc[e];
        return (d[31:15] == 0) ? truncate(d) : 15'h7FFF;
    endfunction
    Vector#(NEpoch, Reg#(Bit#(32))) payTotalLen    <- replicateM(mkRegU);
    Vector#(NEpoch, Reg#(Bool))     feedDone       <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool))     finSentSet  <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool))     finSentClr  <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool))     prioDoneSet <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool))     prioDoneClr <- replicateM(mkReg(False));
    function Bool priorityFinishSent(Integer i) = finSentSet[i] != finSentClr[i];
    function Bool priorityDone(Integer i)       = prioDoneSet[i] != prioDoneClr[i];
    Vector#(NEpoch, Reg#(Bool))     priorityResultHit  <- replicateM(mkRegU);
    Vector#(NEpoch, Reg#(RuleId))   priorityResultRule <- replicateM(mkRegU);
    Vector#(NEpoch, Reg#(Bit#(16))) inFlightNgram  <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(16))) inFlightBitmap <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(16))) inFlightScan   <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(16))) inFlightGram   <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(16))) inFlightRoute  <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(16))) inFlightExact  <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(16))) inFlightPom    <- replicateM(mkReg(0));
    RWire#(Epoch) ngramIncr  <- mkRWire;
    RWire#(Epoch) ngramDecr  <- mkRWire;
    RWire#(Epoch) bitmapIncr <- mkRWire;
    RWire#(Epoch) bitmapDecr <- mkRWire;
    RWire#(Epoch) scanIncr   <- mkRWire;
    RWire#(Epoch) scanDecr   <- mkRWire;   // startScan: pass with no need-lanes
    RWire#(Epoch) scanDecr2  <- mkRWire;   // doScan: last pass drained
    // Gram in-flight is count-based: a 4-wide batch increments by lane count,
    // bloom rejects decrement by lane count, chain completions decrement by 1.
    RWire#(Tuple2#(Epoch, Bit#(3))) gramIncBatch <- mkRWire;
    RWire#(Tuple2#(Epoch, Bit#(3))) gramDecRej   <- mkRWire;
    RWire#(Epoch)                   gramDecChain <- mkRWire;
    RWire#(Epoch) pomIncr    <- mkRWire;
    RWire#(Epoch) pomDecr    <- mkRWire;
    RWire#(Epoch) routeIncr  <- mkRWire;
    RWire#(Epoch) routeDecr  <- mkRWire;
    RWire#(Epoch) exactIncr  <- mkRWire;
    RWire#(Epoch) exactDecr  <- mkRWire;

    // Exact hits are staged before POM so exactMatch draining does not inherit
    // POM BRAM/FIFO readiness as an implicit condition.
    FIFOF#(Tuple2#(Epoch, PomPktMeta))   pomPendingQ <- mkSizedFIFOF(32);
    FIFOF#(PomCtx)                      pomCtxQ     <- mkSizedFIFOF(32);
    FIFOF#(RetireResult)                retireQ     <- mkSizedFIFOF(8);

    // Inter-stage elastic queues: bitmap->scan (gramSideQ, hitPairQ), gram->route.
    FIFOF#(GramSide)   gramSideQ  <- mkSizedFIFOF(16);
    FIFOF#(ScanJob)    hitPairQ   <- mkSizedFIFOF(32);
    FIFOF#(GramResult)                                      gramRouteQ <- mkSizedFIFOF(16);

    function Bool anyFreeEpoch();
        Bool any = False;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1)
            any = any || !epochInUse[i];
        return any;
    endfunction

    function Bool anyEpochInUse();
        Bool any = False;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1)
            any = any || epochInUse[i];
        return any;
    endfunction

    function Bool maybeEpochEq(Maybe#(Epoch) m, Epoch e);
        Bool eq = False;
        case (m) matches
            tagged Valid .x: eq = (x == e);
            tagged Invalid:  eq = False;
        endcase
        return eq;
    endfunction

    function Bit#(16) applyNgramDelta(Bit#(16) cur, Bool inc, Bool dec);
        Bit#(16) next = cur;
        if (inc && !dec)
            next = cur + 1;
        else if (!inc && dec)
            next = cur - 1;
        return next;
    endfunction

    function Rules mkCounterUpdate(Vector#(NEpoch, Reg#(Bit#(16))) cnts,
                                   RWire#(Epoch) inc,
                                   RWire#(Epoch) dec);
        Rules rs = emptyRules;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
            rs = rJoin(rs, (rules
                rule updateInFlight(state == KProcess &&
                                    (maybeEpochEq(inc.wget, fromInteger(i)) ||
                                     maybeEpochEq(dec.wget, fromInteger(i))));
                    cnts[i] <= applyNgramDelta(cnts[i],
                                               maybeEpochEq(inc.wget, fromInteger(i)),
                                               maybeEpochEq(dec.wget, fromInteger(i)));
                endrule
            endrules));
        end
        return rs;
    endfunction

    addRules(mkCounterUpdate(inFlightNgram,  ngramIncr,  ngramDecr));
    addRules(mkCounterUpdate(inFlightPom,    pomIncr,    pomDecr));
    addRules(mkCounterUpdate(inFlightBitmap, bitmapIncr, bitmapDecr));
    for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
        rule updateInFlightScan (state == KProcess);
            Epoch    e   = fromInteger(i);
            Bit#(16) cur = inFlightScan[i];
            if (maybeEpochEq(scanIncr.wget,  e)) cur = cur + 1;
            if (maybeEpochEq(scanDecr.wget,  e)) cur = cur - 1;
            if (maybeEpochEq(scanDecr2.wget, e)) cur = cur - 1;
            inFlightScan[i] <= cur;
        endrule
    end
    addRules(mkCounterUpdate(inFlightRoute,  routeIncr,  routeDecr));
    addRules(mkCounterUpdate(inFlightExact,  exactIncr,  exactDecr));

    // Count-based gram in-flight: per epoch, += batch(inc) − rejects − chain.
    for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
        rule updateInFlightGram (state == KProcess);
            Epoch    e   = fromInteger(i);
            Bit#(16) cur = inFlightGram[i];
            if (gramIncBatch.wget matches tagged Valid {.ge, .gn})
                if (ge == e) cur = cur + zeroExtend(gn);
            if (gramDecRej.wget matches tagged Valid {.re, .rn})
                if (re == e) cur = cur - zeroExtend(rn);
            if (gramDecChain.wget matches tagged Valid .ce)
                if (ce == e) cur = cur - 1;
            inFlightGram[i] <= cur;
        endrule
    end

    // Admission is decided from registers computed the cycle before, so the
    // first slice of a packet is fed in the cycle it is admitted:
    //   admitIdx  - pktIdx of the next packet to admit (packets arrive in order),
    //   admitOkR  - that packet is inside the result reorder window,
    //   freeOkR / freeEpR - a free epoch, not counting the one allocated this cycle.
    // Both flags only turn stale in the safe direction (a retire or a window
    // advance shows up one cycle later).
    Reg#(PktIdx)  admitIdx  <- mkConfigReg(0);
    Reg#(Bool)    admitOkR  <- mkConfigReg(False);
    Reg#(Bool)    freeOkR   <- mkConfigReg(False);
    Reg#(Epoch)   freeEpR   <- mkConfigReg(0);
    RWire#(Epoch) admitNow  <- mkRWire;
    Reg#(Maybe#(Epoch)) admitPrev <- mkDReg(tagged Invalid);   // admitted last cycle

    (* fire_when_enabled, no_implicit_conditions *)
    rule precomputeAdmit;
        PktIdx nextIdx = isValid(admitNow.wget) ? admitIdx + 1 : admitIdx;
        admitOkR <= resultWriter.canAdmit(nextIdx);
        Bool  found = False;
        Epoch chosen = 0;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1)
            if (!found && !epochInUse[i] && admitNow.wget != tagged Valid fromInteger(i)) begin
                chosen = fromInteger(i);
                found  = True;
            end
        freeOkR <= found;
        freeEpR <= chosen;
    endrule

    // feedBeat: stream the armed packet's beats into ngram/exact.  On a packet's
    // first slice it also admits the packet (epoch allocation, 5-tuple and final
    // length; the reader only exposes complete packets, so both are known here).
    // The n-gram front end is NBitmapLanes bytes wide, which is narrower than a
    // 512-bit beat, so each beat is fed as ChunksPerBeat consecutive slices.
    // The beat is retired (advanceBeat) and its end-of-packet side effects are
    // applied only on the final slice; the payload word goes to ExactMatch once,
    // on the first slice.
    Integer chunksPerBeat = 64 / valueOf(NBitmapLanes);
    Reg#(Bit#(3)) feedChunk <- mkReg(0);

    rule feedBeat(state == KProcess && pktReader.beatAvailable &&
                  (metaReady || (pktReader.beat.first && freeOkR && admitOkR)));
        let  bt    = pktReader.beat;
        Bool admit = !metaReady;
        Epoch e    = admit ? freeEpR : curEpoch;

        Bit#(7) laneW  = fromInteger(valueOf(NBitmapLanes));
        Bit#(7) start  = zeroExtend(feedChunk) * laneW;
        Bit#(7) remain = (bt.validBytes > start) ? (bt.validBytes - start) : 0;
        Bit#(7) cnt    = (remain > laneW) ? laneW : remain;
        Bool lastChunk = ((start + cnt) >= bt.validBytes)
                         || (feedChunk == fromInteger(chunksPerBeat - 1));
        Bool pktEnd    = lastChunk && bt.last;

        if (admit) begin
            admitNow.wset(e);
            admitPrev      <= tagged Valid e;
            admitIdx       <= admitIdx + 1;
            epochUseSet[e] <= !epochUseSet[e];
            epochPktIdx[e] <= bt.pktIdx;
            pktMeta.put(e, bt.meta);
            payTotalLen[e] <= bt.payloadLen;
            admitCyc[e]    <= timerTotal.value;
            curEpoch       <= e;
`ifdef NX_TRACE
            $display("TR %0d START e=%0d pkt=%0d len=%0d", timerTotal.value, e, bt.pktIdx, bt.payloadLen);
`endif
            if (!procStarted) begin     // first packet admitted -> start proc clock
                procStarted   <= True;
                firstAdmitCyc <= timerTotal.value;
            end
        end

        // tlast rides the final slice so the extracter flushes its carry there.
        ngram.putBytes(bt.word, start, cnt, pktEnd, e);
        ngramIncr.wset(e);

        if (feedChunk == 0)
            exactMatch.putPayloadWord(bt.word, bt.last, e);

        // feedDone / metaReady: cleared at admission, set at the packet's end
        // (both in one cycle for a single-slice packet).
        if (admit || pktEnd) begin
            feedDone[e] <= pktEnd;
            metaReady   <= !pktEnd;
        end
`ifdef NX_TRACE
        if (pktEnd) $display("TR %0d FEEDDONE e=%0d", timerTotal.value, e);
`endif

        if (lastChunk) begin
            pktReader.advanceBeat;
            feedChunk <= 0;
        end else
            feedChunk <= feedChunk + 1;
    endrule

    // bm1 needs anchor+3 lookahead for lanes 61..63.
    Vector#(NEpoch, Reg#(Bool)) hasPrev <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool)) tailReady <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Vector#(NBitmapLanes, Maybe#(NgramOut)))) prevBatch <- replicateM(mkRegU);

    function Bool epochPipeDone(Epoch e);
        return feedDone[e] &&
               inFlightNgram[e] == 0 &&
               !hasPrev[e] &&
               !tailReady[e] &&
               inFlightBitmap[e] == 0 &&
               inFlightScan[e] == 0 &&
               inFlightGram[e] == 0 &&
               inFlightRoute[e] == 0 &&
               inFlightExact[e] == 0 &&
               inFlightPom[e] == 0;   // a match still in port/offset matching must
    endfunction

    Vector#(NEpoch, Reg#(Bool)) pipeDoneR <- replicateM(mkConfigReg(False));
    (* fire_when_enabled, no_implicit_conditions *)
    rule regPipeDone;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1)
            pipeDoneR[i] <= epochPipeDone(fromInteger(i));
    endrule
    // pipeDoneR lags a cycle: for an epoch admitted last cycle (admitPrev) it
    // still holds the previous packet's value, and a one-slice packet already
    // has feedDone set.
    function Bool epochDoneR(Epoch e) = pipeDoneR[e] && feedDone[e] && admitPrev != tagged Valid e;

    function Bool anyTailReady();
        Bool any = False;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1)
            any = any || tailReady[i];
        return any;
    endfunction

    function Epoch chooseTailReady();
        Epoch chosen = 0;
        Bool found = False;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
            if (!found && tailReady[i]) begin
                chosen = fromInteger(i);
                found = True;
            end
        end
        return chosen;
    endfunction

    function Bit#(18) makeKey18(NgramOut g) =
        {g.gram[21:16], g.gram[13:8], g.gram[5:0]};

    function Tuple3#(Vector#(NBitmapLanes, Bit#(18)),
                     Vector#(NBitmapLanes, Bit#(18)),
                     Vector#(NBitmapLanes, Bool))
        buildKeys(Vector#(NBitmapLanes, Maybe#(NgramOut)) batch,
                  Vector#(NBitmapLanes, Maybe#(NgramOut)) lookahead,
                  Bool                                    hasLookahead);
        Vector#(NBitmapLanes, Bit#(18)) bm0K  = replicate(0);
        Vector#(NBitmapLanes, Bit#(18)) bm1K  = replicate(0);
        Vector#(NBitmapLanes, Bool)     bm1V  = replicate(False);
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            case (batch[i]) matches
                tagged Valid .g: bm0K[i] = makeKey18(g);
                tagged Invalid:  bm0K[i] = 0;
            endcase
            Maybe#(NgramOut) src = tagged Invalid;
            if (i + 3 < valueOf(NBitmapLanes))
                src = batch[i + 3];
            else if (hasLookahead)
                src = lookahead[i + 3 - valueOf(NBitmapLanes)];
            case (src) matches
                tagged Valid .g: begin bm1K[i] = makeKey18(g); bm1V[i] = True; end
                tagged Invalid:  begin bm1K[i] = 0;            bm1V[i] = False; end
            endcase
        end
        return tuple3(bm0K, bm1K, bm1V);
    endfunction

    // A finished packet's last batch (tailReady) has no lookahead and is looked
    // up on its own.  A packet's first batch is only stored, which leaves the
    // bitmap ports free in that cycle, so a pending tail goes there; flushTail
    // covers the case where no new packet follows.
    function Action lookupBatch(Epoch e, Vector#(NBitmapLanes, Maybe#(NgramOut)) grams,
                                Vector#(NBitmapLanes, Maybe#(NgramOut)) lookahead,
                                Bool hasLookahead);
        action
            match { .bm0K, .bm1K, .bm1V } = buildKeys(grams, lookahead, hasLookahead);
            bm0_s1.lookup(bm0K);
            bm0_s2.lookup(bm0K);
            bm1.lookup(bm1K);
            gramSideQ.enq(GramSide { epoch: e, grams: grams, nextValid: bm1V, nextKey: bm1K });
            bitmapIncr.wset(e);
        endaction
    endfunction

    rule absorbNgramBatch(state == KProcess && ngram.gramsReady);
        let b <- ngram.getGrams;
        Epoch e = b.epoch;
        Epoch t = chooseTailReady;
        ngramDecr.wset(e);
        Vector#(NEpoch, Bool) hp = readVReg(hasPrev);
        Vector#(NEpoch, Bool) tr = readVReg(tailReady);
        if (!hasPrev[e]) begin
            // t != e: a tail-ready epoch still holds its last batch (hasPrev).
            if (anyTailReady) begin
                lookupBatch(t, prevBatch[t], prevBatch[t], False);
                hp[t] = False;
                tr[t] = False;
            end
            hp[e] = True;
        end else
            lookupBatch(e, prevBatch[e], b.grams, True);
        prevBatch[e] <= b.grams;
        tr[e] = b.last;
        writeVReg(hasPrev, hp);
        writeVReg(tailReady, tr);
    endrule

    // Both rules drive the same bitmap lookup ports and gramSideQ.  The steady
    // gram stream goes first; flushTail (a finished packet's last batch) takes
    // the next gap.  Gaps are guaranteed: with all NEpoch epochs busy no new
    // packet is admitted, so the gram stream stops.
    (* descending_urgency = "absorbNgramBatch, flushTail" *)
    rule flushTail(state == KProcess && anyTailReady);
        Epoch e = chooseTailReady;
        lookupBatch(e, prevBatch[e], prevBatch[e], False);
        hasPrev[e] <= False;
        tailReady[e] <= False;
    endrule

    rule pairBitmapResults;
        let hits_s1 <- bm0_s1.result;
        let hits_s2 <- bm0_s2.result;
        let hits_b1 <- bm1.result;
        let side = gramSideQ.first; gramSideQ.deq;
        let e = side.epoch; let grams = side.grams; let bm1V = side.nextValid; let bm1K = side.nextKey;

        Vector#(NBitmapLanes, Bool)     needCuckoo = newVector;
        Vector#(NBitmapLanes, Bool)     needS1Too  = newVector;
        Vector#(NBitmapLanes, Bit#(18)) keyA       = newVector;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            Bool valid = isValid(grams[i]);
            Bool s1    = hits_s1[i] && valid;
            Bool s2    = hits_s2[i] && valid;
            Bool s2ok  = s2 && bm1V[i] && hits_b1[i];
            Bool need  = s1 || s2ok;
            needCuckoo[i] = need;
            needS1Too[i]  = s1 && s2ok;
            keyA[i]       = s2ok ? bm1K[i] : 0;
        end
        bitmapDecr.wset(e);
        scanIncr.wset(e);
        hitPairQ.enq(ScanJob { epoch: e, needA: needCuckoo, needB: needS1Too, grams: grams, keyA: keyA });
    endrule

    // startScan sets up the next pass while doScan drains the current one.
    Reg#(Bool)                                 scanPhaseB  <- mkReg(False);   // running the key-0 pass
    Reg#(Bit#(7))                              scanIdx     <- mkReg(0);   // rank cursor
    FIFOF#(ScanPass)                           scanPassQ   <- mkFIFOF;
    FIFOF#(BloomReq4)                          bloomFeedQ  <- mkFIFOF;

    rule startScan;
        let job = hitPairQ.first;
        let e = job.epoch; let needA = job.needA; let needB = job.needB; let grams = job.grams; let keyA = job.keyA;
        Bool hasB = pack(needB) != 0;
        let  need = scanPhaseB ? needB : needA;
        Vector#(NBitmapLanes, Bit#(18)) bm1K = scanPhaseB ? replicate(0) : keyA;
        // The entry stays at the head until its last pass has been set up;
        // inFlightScan is decremented once, when that last pass finishes.
        Bool lastPass = scanPhaseB || !hasB;
        if (lastPass) begin
            hitPairQ.deq;
            scanPhaseB <= False;
        end else
            scanPhaseB <= True;

        // effective select = bitmap-need AND a real gram on that lane
        Vector#(NBitmapLanes, Bool)     sel = newVector;
        Vector#(NBitmapLanes, NgramOut) gUn = newVector;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            sel[i] = need[i] && isValid(grams[i]);
            gUn[i] = validValue(grams[i]);
        end
        Bit#(NBitmapLanes) selBits = pack(sel);

        // exclusive prefix rank of each lane = popcount of selected lanes below it
        // (independent masked popcounts = balanced trees, O(n), no 64-deep chain).
        Vector#(NBitmapLanes, Bit#(7)) rankV = newVector;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            Bit#(NBitmapLanes) below = selBits & ((1 << i) - 1);
            rankV[i] = zeroExtend(pack(countOnes(below)));
        end

        if (selBits == 0) begin
            if (lastPass) scanDecr.wset(e);
        end else
            scanPassQ.enq(ScanPass { epoch: e, last: lastPass, sel: sel, rank: rankV, gram: gUn,
                                     bm1K: bm1K, count: zeroExtend(pack(countOnes(selBits))) });
    endrule

    rule doScan;
        let sp = scanPassQ.first;
        Bit#(7) n = sp.count;
        // The next 4 need-lanes are the lanes whose exclusive rank == scanIdx..+3.
        // These are FOUR INDEPENDENT rank-match selects (not chained) -> shallow.
        // scanIdx only ever steps by 4, so rank == scanIdx + k is exactly
        // rank[6:2] == scanIdx[6:2] && rank[1:0] == k (no adders).  Ranks of the
        // selected lanes are exactly 0..n-1, so "some lane matched" == (t < n).
        function Maybe#(BloomReq) laneForRank(Integer k);
            NgramOut g  = unpack(0);
            Bit#(18) kk = 0;
            Bool found  = False;
            for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1)
                if (sp.sel[i] && sp.rank[i][6:2] == scanIdx[6:2]
                              && sp.rank[i][1:0] == fromInteger(k)) begin
                    g     = sp.gram[i];
                    kk    = sp.bm1K[i];
                    found = True;
                end
            Bit#(32) key18 = zeroExtend(makeKey18(g));
            let req = mkBloomReq(key18, g.gram[23:0], kk, g.anchor, sp.epoch);
            return found ? tagged Valid req : tagged Invalid;
        endfunction

        BloomReq4 reqs = newVector;
        for (Integer k = 0; k < 4; k = k + 1) reqs[k] = laneForRank(k);
        Bit#(3) cnt = 0;
        for (Integer k = 0; k < 4; k = k + 1) if (isValid(reqs[k])) cnt = cnt + 1;

        if (cnt != 0) begin
            bloomFeedQ.enq(reqs);
            gramIncBatch.wset(tuple2(sp.epoch, cnt));
        end
        if (scanIdx + 4 >= n) begin
            if (sp.last) scanDecr2.wset(sp.epoch);
            scanPassQ.deq;
            scanIdx <= 0;
        end else
            scanIdx <= scanIdx + 4;
    endrule

    rule feedBloom;
        gram.lookupReq4(bloomFeedQ.first); bloomFeedQ.deq;
    endrule

    // Chain results (passes) retire 1/cycle here; bloom rejects retire in bulk
    // via gram.rejectReport (consumeBloomRejects) and never enter this stream.
    rule collectGramHits(state == KProcess);
        let gr <- gram.lookupResp;
        if (gr.lastInChain)
            gramDecChain.wset(gr.epoch);
        if (gr.hit) begin
            routeIncr.wset(gr.epoch);
            gramRouteQ.enq(gr);
        end
    endrule

    rule consumeBloomRejects(state == KProcess);
        let ri <- gram.getReject;
        gramDecRej.wset(tuple2(ri.epoch, ri.count));
    endrule

    rule routeGramResult(state == KProcess);
        let gr = gramRouteQ.first; gramRouteQ.deq;
        routeDecr.wset(gr.epoch);
        exactIncr.wset(gr.epoch);
        exactMatch.putRequest(gr.vreq, gr.epoch);
`ifdef NX_TRACE
        $display("TR %0d ROUTE e=%0d rule=%0d", timerTotal.value, gr.epoch, gr.vreq.ruleId);
`endif
    endrule

    FIFOF#(ExactHit) pomHoldQ <- mkSizedFIFOF(64);

    rule drainExact(state == KProcess);
        let r <- exactMatch.getResult;
        exactDecr.wset(r.epoch);
        if (r.hit) begin
            // Count it as in-flight POM work from here: while it sits in pomHoldQ it
            // is in neither inFlightExact nor inFlightPom otherwise, and epochPipeDone
            // would finalize the epoch and drop the match.
            pomIncr.wset(r.epoch);
            pomHoldQ.enq(ExactHit { epoch: r.epoch, ruleId: r.ruleId, matchPos: r.matchPos, endOff: r.endOff });
`ifdef NX_TRACE
            $display("TR %0d EXHIT e=%0d rule=%0d pos=%0d end=%0d", timerTotal.value, r.epoch, r.ruleId, r.matchPos, r.endOff);
`endif
        end
    endrule

    FIFOF#(PomRelease) pomRelQ <- mkFIFOF;

    rule releasePomCandidate(state == KProcess);
        let h = pomHoldQ.first; pomHoldQ.deq;
        let e = h.epoch;
        pomRelQ.enq(PomRelease { epoch: e, endOff: h.endOff, meta: PomPktMeta {
                ruleId:     h.ruleId,
                ipProto:    pktMeta.getProto(e),
                srcPort:    pktMeta.getSrcPort(e),
                dstPort:    pktMeta.getDstPort(e),
                icmpType:   pktMeta.getIcmpType(e),
                icmpCode:   pktMeta.getIcmpCode(e),
                matchPos:   h.matchPos,
                payloadLen: payTotalLen[e]
            } });
    endrule

    rule checkPomEnd(state == KProcess);
        let rel = pomRelQ.first; pomRelQ.deq;
        let e = rel.epoch; let m = rel.meta;
        if (rel.endOff <= m.payloadLen)
            pomPendingQ.enq(tuple2(e, m));
        else begin
            pomDecr.wset(e);   // rejected here, so it never reaches collectPortResult
`ifdef NX_TRACE
            $display("TR %0d ENDREJ e=%0d rule=%0d", timerTotal.value, e, m.ruleId);
`endif
        end
    endrule

    // Keep POM backpressure out of drainExact's firing condition.
    rule sendToPom;
        match { .e, .m } = pomPendingQ.first; pomPendingQ.deq;
        portMatch.putMeta(m);
        pomCtxQ.enq(PomCtx { epoch: e, pktIdx: epochPktIdx[e] });
    endrule

    // checkPomEnd (rejects) and collectPortResult share the single pomDecr
    // RWire; whichever loses waits one cycle.  Rejects are rare.
    (* descending_urgency = "checkPomEnd, collectPortResult" *)
    rule collectPortResult(state == KProcess);
        let pr <- portMatch.getResult;
        let ctx = pomCtxQ.first; pomCtxQ.deq;
        pomDecr.wset(ctx.epoch);
        prioStage.putCandidate(PriorityCandidate {
            epoch:  ctx.epoch,
            pktIdx: ctx.pktIdx,
            hit:    pr.hit,
            ruleId: pr.ruleId
        });
`ifdef NX_TRACE
        $display("TR %0d POM e=%0d pkt=%0d hit=%0d rule=%0d", timerTotal.value, ctx.epoch, ctx.pktIdx, pr.hit, pr.ruleId);
`endif
    endrule

    function Maybe#(Epoch) lowestReady(Vector#(NEpoch, Bool) ready);
        Maybe#(Epoch) sel = tagged Invalid;
        for (Integer i = valueOf(NEpoch) - 1; i >= 0; i = i - 1)
            if (ready[i]) sel = tagged Valid fromInteger(i);
        return sel;
    endfunction
    function Bool canFinish(Integer i) =
        epochInUse[i] && epochDoneR(fromInteger(i)) && inFlightPom[i] == 0 && !priorityFinishSent(i);
    function Bool canRetire(Integer i) =
        epochInUse[i] && epochDoneR(fromInteger(i)) && priorityDone(i);

    rule finishPriority(state == KProcess &&& lowestReady(genWith(canFinish)) matches tagged Valid .e);
        prioStage.finishEpoch(e, epochPktIdx[e]);
`ifdef NX_TRACE
        $display("TR %0d FINISH e=%0d pkt=%0d", timerTotal.value, e, epochPktIdx[e]);
`endif
        finSentSet[e] <= !finSentSet[e];
    endrule

    rule collectPriorityResult(state == KProcess);
        let r <- prioStage.getResult;
        prioDoneSet[r.epoch]        <= !prioDoneSet[r.epoch];
        priorityResultHit[r.epoch]  <= r.hit;
        priorityResultRule[r.epoch] <= r.ruleId;
`ifdef NX_TRACE
        $display("TR %0d PRIO e=%0d hit=%0d rule=%0d", timerTotal.value, r.epoch, r.hit, r.ruleId);
`endif
    endrule

    // Retiring only releases the epoch's control flags.  Its data registers
    // are rewritten (feedBeat, collectPriorityResult) before being read again.
    // Latencies are computed per epoch from registers and then selected, so the
    // arbiter's choice does not sit in front of the 32-bit subtract.
    Vector#(NEpoch, Bit#(15)) latencyNow = map(e2eLatency, genWith(fromInteger));

    // feedBeat allocates an epoch (epochUseSet) and retireEpoch frees one (epochUseClr).
    rule retireEpoch(state == KProcess &&& lowestReady(genWith(canRetire)) matches tagged Valid .e);
`ifdef NX_TRACE
        $display("TR %0d RETIRE e=%0d pkt=%0d hit=%0d rule=%0d", timerTotal.value, e, epochPktIdx[e], priorityResultHit[e], priorityResultRule[e]);
`endif
        retireQ.enq(RetireResult { pktIdx:  epochPktIdx[e],
                                   hit:     priorityResultHit[e],
                                   ruleId:  priorityResultHit[e] ? priorityResultRule[e] : 0,
                                   latency: latencyNow[e] });
        epochUseClr[e] <= !epochUseClr[e];
        finSentClr[e]  <= !finSentClr[e];
        prioDoneClr[e] <= !prioDoneClr[e];
    endrule

    rule writeRetiredResult(state == KProcess && resultWriter.canAccept(retireQ.first.pktIdx));
        let r = retireQ.first; retireQ.deq;
        resultWriter.addResult(r.pktIdx, r.hit, r.ruleId, r.latency);
        lastRetireCyc <= timerTotal.value;
    endrule

    // Idle-detect: once processing has started and the kernel has been fully idle
    // (no buffered beats, no epoch in flight, not mid-packet) for a while, the run
    // is done -> emit the total process-cycle span as the result-stream footer.
    function Bool anyEpochBusy();
        Bool b = False;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) b = b || epochInUse[i];
        return b;
    endfunction
    rule procIdleTrack(state == KProcess);
        if (procStarted && !pktReader.beatAvailable && !anyEpochBusy() && !metaReady)
            idleCnt <= idleCnt + 1;
        else
            idleCnt <= 0;
    endrule
    rule emitProcFooter(state == KProcess && procStarted && !footerDone
                        && idleCnt > 32'd2000);
        resultWriter.emitFooter(lastRetireCyc - firstAdmitCyc);
        footerDone <= True;
    endrule

`ifdef NX_DEBUG
    // Simulation-only (compile with -D NX_DEBUG) watchdog: when wedged, dumps the frozen per-epoch state every 200k
    // cycles so the stuck counter / backpressured FIFO is visible.
    rule watchdog(state == KProcess && (timerTotal.value - wdLast) > 32'd200000);
        wdLast <= timerTotal.value;
        $display("=== WATCHDOG cyc=%0d ===", timerTotal.value);
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
            if (epochInUse[i])
                $display("  ep%0d pkt=%0d fd=%0d hp=%0d tr=%0d | ng=%0d bm=%0d sc=%0d gr=%0d rt=%0d ex=%0d",
                    i, epochPktIdx[i], feedDone[i], hasPrev[i], tailReady[i],
                    inFlightNgram[i], inFlightBitmap[i], inFlightScan[i],
                    inFlightGram[i], inFlightRoute[i], inFlightExact[i]);
        end
        $display("  Q: gramSide=%0d hitPair=%0d gramRoute=%0d retire=%0d pomPend=%0d pomCtx=%0d metaRdy=%0d pktRdy=%0d",
                 gramSideQ.notEmpty, hitPairQ.notEmpty, gramRouteQ.notEmpty,
                 retireQ.notEmpty, pomPendingQ.notEmpty, pomCtxQ.notEmpty,
                 metaReady, pktReader.beatAvailable);
        $display("  ADM: beatAvail=%0d anyFreeEpoch=%0d nextOut=%0d",
                 pktReader.beatAvailable, anyFreeEpoch, resultWriter.dbgNextOut);
    endrule
`endif

    // Free-running: no process-done / write / done phases. Once DB is loaded the
    // kernel stays in KProcess and matches packets forever.

    // Boot once out of reset: kick the DB section loader (it self-terminates at
    // DLDone after the bloom section) and reset the result reorder buffer.
    rule selfBoot(!booted && state == KIdle);
        booted <= True;
        dataLoader.startLoad(0);   // dbBytes advisory; FSM ends at DLDone
        timerTotal.markStart;
        state <= KInit;
    endrule

    rule doInit(state == KInit && dataLoader.loadDone);
        $display("KM init done");
        // Emit db_load cycle count as the result stream's first (header) beat so
        // the host can separate DB-load time from packet-processing time.
        resultWriter.emitHeader(timerTotal.value);
        pktReader.enable;          // begin draining s_axis_pkt
        state <= KProcess;
    endrule

    interface s_axis_db = dbStream.pins;
    interface s_axis_pkt = pktStream.pins;
    interface m_axis_result = resStream.pins;
endmodule

endpackage
