package KernelMain;

import FIFO::*;
import FIFOF::*;
import Vector::*;

import BitmapUram::*;
import CycleCounter::*;
import ExactPatternTable::*;
import GramMatcher::*;
import NgramExtracter::*;
import PacketMeta::*;
import ExactMatch::*;
import PortOffsetMatcher::*;
import Priority::*;
import DataLoader::*;
import PacketReader::*;
import ResultWriter::*;
import AxiStream::*;
import DbStreamLoader::*;
import ResultStreamWriter::*;
import PacketStreamReader::*;

interface KernelMainIfc;
    interface AxiStreamSlavePinsIfc#(512) s_axis_db;
    interface AxiStreamSlaveUserPinsIfc#(512, 128) s_axis_pkt;
    interface AxiStreamMasterPinsIfc#(32) m_axis_result;
endinterface

typedef 3 MemPortCnt;
typedef 8 NEpoch;
typedef Bit#(3) Epoch;

typedef enum { KIdle, KInit, KProcess, KWritePrep, KWrite, KDone } KState deriving (Bits, Eq, FShow);

typedef struct {
    Epoch    epoch;
    Bit#(32) pktIdx;
} PomCtx deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) pktIdx;
    Bool     hit;
    Bit#(16) ruleId;
    Bit#(15) latency;
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
    AxiStreamSlaveIfc#(512) dbStream <- mkAxiStreamSlave_512;
    DbStreamLoaderIfc     dataLoader   <- mkDbStreamLoader(bm0_s1, bm0_s2, bm1, gram, patternTable, portMatch, prioStage, dbStream);
    AxiStreamSlaveUserIfc#(512, 128) pktStream <- mkAxiStreamSlaveUser_512_128;
    PacketStreamReaderIfc pktReader <- mkPacketStreamReader(pktStream);
    AxiStreamMasterIfc#(32) resStream <- mkAxiStreamMaster_32;
    ResultStreamWriterIfc resultWriter <- mkResultStreamWriter(resStream);

    CycleCounterIfc timerDb    <- mkCycleCounter;
    CycleCounterIfc timerPkt   <- mkCycleCounter;
    CycleCounterIfc timerTotal <- mkCycleCounter;

    Reg#(KState) state  <- mkReg(KIdle);
    Reg#(Bool)   booted <- mkReg(False);

    Reg#(Bit#(6))   payOff       <- mkReg(0);
    Reg#(Epoch)     curEpoch     <- mkReg(0);
    Reg#(Bit#(32))  curPktIdx    <- mkReg(0);
    Reg#(Bool)      metaReady    <- mkReg(False);

    Vector#(NEpoch, Reg#(Bool))     epochInUse    <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bit#(32))) epochPktIdx    <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(32))) admitCyc       <- replicateM(mkReg(0));
    Reg#(Bit#(32)) wdLast <- mkReg(0);  // DEBUG watchdog last-dump cycle
    Reg#(Bool)     procStarted  <- mkReg(False);
    Reg#(Bit#(32)) firstAdmitCyc <- mkReg(0);
    Reg#(Bit#(32)) lastRetireCyc <- mkReg(0);
    Reg#(Bit#(32)) idleCnt       <- mkReg(0);
    Reg#(Bool)     footerDone    <- mkReg(False);
    function Bit#(15) e2eLatency(Epoch e);
        Bit#(32) d = timerTotal.value - admitCyc[e];
        return (d[31:15] == 0) ? truncate(d) : 15'h7FFF;
    endfunction
    Vector#(NEpoch, Reg#(Bit#(32))) payTotalLen    <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bool))     feedDone       <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool))     priorityFinishSent <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool))     priorityDone       <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bool))     priorityResultHit  <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bit#(16))) priorityResultRule <- replicateM(mkReg(0));
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
    RWire#(Epoch) scanDecr   <- mkRWire;
    
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

    // Include inter-stage queues in E2E spans so queueing stalls are counted.
    FIFOF#(Tuple4#(Epoch,
                   Vector#(NBitmapLanes, Maybe#(NgramOut)),
                   Vector#(NBitmapLanes, Bool),
                   Vector#(NBitmapLanes, Bit#(18))))        gramSideQ  <- mkSizedFIFOF(16);
    FIFOF#(Tuple4#(Epoch,
                   Vector#(NBitmapLanes, Bool),
                   Vector#(NBitmapLanes, Maybe#(NgramOut)),
                   Vector#(NBitmapLanes, Bit#(18))))        hitPairQ   <- mkSizedFIFOF(16);
    FIFOF#(GramResult)                                      gramRouteQ <- mkSizedFIFOF(16);

    Reg#(Bit#(32)) dataLoaderCycles   <- mkReg(0);
    Reg#(Bit#(32)) packetReaderCycles <- mkReg(0);
    Reg#(Bit#(32)) payloadFeedCycles  <- mkReg(0);
    Reg#(Bit#(32)) ngramCycles        <- mkReg(0);
    Reg#(Bit#(32)) bitmapCycles       <- mkReg(0);
    Reg#(Bit#(32)) gramCycles         <- mkReg(0);
    Reg#(Bit#(32)) bloomCycles        <- mkReg(0);
    Reg#(Bit#(32)) exactCycles        <- mkReg(0);
    Reg#(Bit#(32)) pomCycles          <- mkReg(0);
    Reg#(Bit#(32)) resultWriterCycles <- mkReg(0);

    E2ESpanIfc dataLoaderSpan   <- mkE2ESpan;
    E2ESpanIfc packetReaderSpan <- mkE2ESpan;
    E2ESpanIfc payloadFeedSpan  <- mkE2ESpan;
    E2ESpanIfc ngramSpan        <- mkE2ESpan;
    E2ESpanIfc bitmapSpan       <- mkE2ESpan;
    E2ESpanIfc gramSpan         <- mkE2ESpan;
    E2ESpanIfc bloomSpan        <- mkE2ESpan;
    E2ESpanIfc exactSpan        <- mkE2ESpan;
    E2ESpanIfc pomSpan          <- mkE2ESpan;
    E2ESpanIfc resultWriterSpan <- mkE2ESpan;

    Reg#(Bit#(32)) gramsExtracted     <- mkReg(0);
    Reg#(Bit#(32)) bitmapPassed       <- mkReg(0);
    Reg#(Bit#(32)) gramLookups        <- mkReg(0);
    Reg#(Bit#(32)) gramHits           <- mkReg(0);
    Reg#(Bit#(32)) bloomRejects       <- mkReg(0);
    Reg#(Bit#(32)) exactChecks        <- mkReg(0);
    Reg#(Bit#(32)) exactHits          <- mkReg(0);
    Reg#(Bit#(32)) exactMisses        <- mkReg(0);
    Reg#(Bit#(32)) pomChecks          <- mkReg(0);
    Reg#(Bit#(32)) pomHits            <- mkReg(0);
    Reg#(Bit#(32)) pomMisses          <- mkReg(0);
    Reg#(Bit#(32)) noMatchPkts        <- mkReg(0);
    Reg#(Bit#(32)) stage2Checked      <- mkReg(0);
    Reg#(Bit#(32)) stage2Passed       <- mkReg(0);
    Reg#(Bit#(32)) gapBackend         <- mkReg(0);
    Reg#(Bit#(32)) gapHbm             <- mkReg(0);
    Reg#(Bit#(32)) gapReaderOther     <- mkReg(0);
    Reg#(Bit#(32)) gapMetaWait        <- mkReg(0);
    Reg#(Bit#(32)) gapNextStart       <- mkReg(0);
    Reg#(Bit#(32)) readerDescCycles   <- mkReg(0);
    Reg#(Bit#(32)) readerStartCycles  <- mkReg(0);
    Reg#(Bit#(32)) readerFirstLineWaitCycles <- mkReg(0);
    Reg#(Bit#(32)) readerRespCycles   <- mkReg(0);
    Reg#(Bit#(32)) epochFullCycles    <- mkReg(0);
    Reg#(Bit#(32)) resultAcceptBlockCycles <- mkReg(0);
    Reg#(Bit#(32)) exactInputBlockCycles <- mkReg(0);
    Reg#(Bit#(32)) lastNextCycle      <- mkReg(0);
    Reg#(Bool)     awaitingFirstFeed  <- mkReg(False);
    Reg#(ResultSummary) resultSummary <- mkReg(unpack(0));

    // DB now arrives via s_axis_db (DbStreamLoader), not AXI4 memory reads.

    function Bit#(32) countValidGrams(Vector#(NBitmapLanes, Maybe#(NgramOut)) grams);
        Bit#(32) total = 0;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            case (grams[i]) matches
                tagged Valid .g: total = total + 1;
                tagged Invalid:  total = total;
            endcase
        end
        return total;
    endfunction

    // Only count bitmap hits on lanes that carried a real gram.  Padding
    // lanes feed key=0 into the bitmap lookup and would otherwise inflate
    // the counter without ever issuing a GHT lookup downstream.
    function Bit#(32) countHits(
        Vector#(NBitmapLanes, Bool) hits,
        Vector#(NBitmapLanes, Maybe#(NgramOut)) grams
    );
        Bit#(32) total = 0;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1)
            if (hits[i] && isValid(grams[i])) total = total + 1;
        return total;
    endfunction

    function Bool anyFreeEpoch();
        Bool any = False;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1)
            any = any || !epochInUse[i];
        return any;
    endfunction

    function Epoch chooseFreeEpoch();
        Epoch chosen = 0;
        Bool found = False;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
            if (!found && !epochInUse[i]) begin
                chosen = fromInteger(i);
                found = True;
            end
        end
        return chosen;
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
    addRules(mkCounterUpdate(inFlightScan,   scanIncr,   scanDecr));
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

    // Packets now arrive over s_axis_pkt (PacketStreamReader), not AXI4 memory.

    // Result now leaves over m_axis_result (ResultStreamWriter), not AXI4 memory.

    rule countModuleCycles(
        (state == KInit && !dataLoader.loadDone) ||
        (state == KProcess)
    );
        Bit#(32) now = timerTotal.value;

        if (state == KInit && !dataLoader.loadDone) begin
            dataLoaderCycles <= dataLoaderCycles + 1;
            dataLoaderSpan.mark(now);
        end

        if (state == KProcess) begin
            Bool bitmapInner = !bm0_s1.idle || !bm0_s2.idle || !bm1.idle;
            Bool exactInner  = exactMatch.inputPending || exactMatch.notEmpty;
            Bool pomInner    = portMatch.processing    || !prioStage.idle;

            if (pktReader.busy) begin
                packetReaderCycles <= packetReaderCycles + 1;
                packetReaderSpan.mark(now);
            end
            if (!ngram.idle) begin
                ngramCycles <= ngramCycles + 1;
                ngramSpan.mark(now);
            end
            if (bitmapInner) bitmapCycles <= bitmapCycles + 1;
            if (bitmapInner || gramSideQ.notEmpty || !ngram.idle)
                bitmapSpan.mark(now);
            if (!gram.idle) gramCycles <= gramCycles + 1;
            if (!gram.idle || hitPairQ.notEmpty)
                gramSpan.mark(now);
            if (gram.bloomBusy) begin
                bloomCycles <= bloomCycles + 1;
                bloomSpan.mark(now);
            end
            if (exactInner) exactCycles <= exactCycles + 1;
            if (exactInner || gramRouteQ.notEmpty)
                exactSpan.mark(now);
            if (pomInner) pomCycles <= pomCycles + 1;
            if (pomInner || pomPendingQ.notEmpty || pomCtxQ.notEmpty)
                pomSpan.mark(now);
        end

    endrule

    rule countGaps(state == KProcess);
        if (pktReader.pktDone)
            gapBackend <= gapBackend + 1;
        else if (pktReader.feedAwaitingLine)
            gapHbm <= gapHbm + 1;
        else if (pktReader.pktReady && !metaReady)
            gapMetaWait <= gapMetaWait + 1;
        else if (pktReader.busy && !pktReader.pktReady)
            gapReaderOther <= gapReaderOther + 1;
    endrule

    rule countReaderBreakdown(state == KProcess);
        if (pktReader.descBusy)
            readerDescCycles <= readerDescCycles + 1;
        if (pktReader.startBusy)
            readerStartCycles <= readerStartCycles + 1;
        if (pktReader.startAwaitingPayload)
            readerFirstLineWaitCycles <= readerFirstLineWaitCycles + 1;
        if (pktReader.payloadRespBusy)
            readerRespCycles <= readerRespCycles + 1;
    endrule

    rule countBackpressure(state == KProcess);
        if (pktReader.beatAvailable && !anyFreeEpoch)
            epochFullCycles <= epochFullCycles + 1;
        if (retireQ.notEmpty && !resultWriter.canAccept(retireQ.first.pktIdx))
            resultAcceptBlockCycles <= resultAcceptBlockCycles + 1;
    endrule

    // Admission gate (resultWriter.canAdmit): do not start a packet that would
    // run more than the reorder window ahead of the in-order output head, so the
    // reorder buffer can never alias -> no deadlock under mixed packet sizes.
    // DECOUPLED feed (see fix.md). Split into admission + feed so the gate
    // (reads resultWriter.canAdmit) is NOT in the same rule that drives the
    // matcher (which feeds back into resultWriter) -> no scheduling cycle, like
    // the old latchMeta/feedPayloadWord split.
    //
    // startPacket: on a FIRST beat, with a free epoch and within the reorder
    // window, allocate the epoch and arm feeding. Does not feed or consume the
    // beat (so it never touches the matcher / resultWriter write path).
    rule startPacket(state == KProcess && !metaReady && pktReader.beatAvailable
                     && pktReader.beat.first && anyFreeEpoch
                     && resultWriter.canAdmit(pktReader.beat.pktIdx));
        Epoch e = chooseFreeEpoch;
        epochInUse[e]  <= True;
        epochPktIdx[e] <= pktReader.beat.pktIdx;
        admitCyc[e]    <= timerTotal.value;
        curEpoch       <= e;
        curPktIdx      <= pktReader.beat.pktIdx;
        metaReady      <= True;     // "packet in progress"
        // CRITICAL: clear the stale feedDone left True by the PREVIOUS packet that
        // used this epoch. feedDone is only ever set True (on last beat) and freed
        // epochs keep it set; on reuse, epochPipeDone would see feedDone=True + all
        // counters 0 and FINALIZE this packet before its first beat is even fed
        // (the lost-match bug, exposed when feed is backpressured after admission).
        feedDone[e]    <= False;
        if (!procStarted) begin     // first packet admitted -> start proc clock
            procStarted   <= True;
            firstAdmitCyc <= timerTotal.value;
        end
    endrule

    // feedBeat: stream the armed packet's beats into ngram/exact; capture the
    // 5-tuple + final length on the last beat. No resultWriter read -> no cycle.
    rule feedBeat(state == KProcess && metaReady && pktReader.beatAvailable);
        let bt = pktReader.beat;
        pktReader.advanceBeat;
        payloadFeedCycles <= payloadFeedCycles + 1;

        Epoch e = curEpoch;
        ngram.putBytes(bt.word, 0, bt.validBytes, bt.last, e);
        exactMatch.putPayloadWord(bt.word, bt.last, e);
        ngramIncr.wset(e);
        payTotalLen[e] <= bt.payloadLen;   // running length; final on last beat

        if (bt.last) begin
            pktMeta.put(e, bt.meta);
            feedDone[e] <= True;
            metaReady   <= False;
        end
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
                                      // not let the epoch finalize early (lost match
                                      // under line-rate; masked in draft by throttle)
    endfunction

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

    rule absorbNgramBatch(state == KProcess && ngram.gramsReady);
        let b <- ngram.getGrams;
        Epoch e = b.epoch;
        ngramDecr.wset(e);
        if (!hasPrev[e]) begin
            prevBatch[e] <= b.grams;
            hasPrev[e]   <= True;
            tailReady[e] <= b.last;
        end else begin
            let prev = prevBatch[e];
            match { .bm0K, .bm1K, .bm1V } = buildKeys(prev, b.grams, True);
            bm0_s1.lookup(bm0K);
            bm0_s2.lookup(bm0K);
            bm1.lookup(bm1K);
            gramSideQ.enq(tuple4(e, prev, bm1V, bm1K));
            gramsExtracted <= gramsExtracted + countValidGrams(prev);
            bitmapIncr.wset(e);
            prevBatch[e] <= b.grams;
            tailReady[e] <= b.last;
        end
    endrule

    rule flushTail(state == KProcess && anyTailReady);
        Epoch e = chooseTailReady;
        let prev = prevBatch[e];
        match { .bm0K, .bm1K, .bm1V } = buildKeys(prev, prev, False);
        bm0_s1.lookup(bm0K);
        bm0_s2.lookup(bm0K);
        bm1.lookup(bm1K);
        gramSideQ.enq(tuple4(e, prev, bm1V, bm1K));
        gramsExtracted <= gramsExtracted + countValidGrams(prev);
        bitmapIncr.wset(e);
        hasPrev[e] <= False;
        tailReady[e] <= False;
    endrule

    rule pairBitmapResults;
        let hits_s1 <- bm0_s1.result;
        let hits_s2 <- bm0_s2.result;
        let hits_b1 <- bm1.result;
        match { .e, .grams, .bm1V, .bm1K } = gramSideQ.first; gramSideQ.deq;

        Vector#(NBitmapLanes, Bool) needCuckoo = newVector;
        Bit#(32) bm0Hits     = 0;
        Bit#(32) bm0S2Hits   = 0;
        Bit#(32) bm0S2AndBm1 = 0;
        Bit#(32) cuckooCnt   = 0;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            Bool valid = isValid(grams[i]);
            Bool s1    = hits_s1[i] && valid;
            Bool s2    = hits_s2[i] && valid;
            Bool s2ok  = s2 && bm1V[i] && hits_b1[i];
            Bool need  = s1 || s2ok;
            needCuckoo[i] = need;
            if (s1 || s2) bm0Hits     = bm0Hits     + 1;
            if (s2)       bm0S2Hits   = bm0S2Hits   + 1;
            if (s2ok)     bm0S2AndBm1 = bm0S2AndBm1 + 1;
            if (need)     cuckooCnt   = cuckooCnt   + 1;
        end
        bitmapPassed  <= bitmapPassed  + bm0Hits;
        stage2Checked <= stage2Checked + bm0S2Hits;
        stage2Passed  <= stage2Passed  + bm0S2AndBm1;
        bitmapDecr.wset(e);
        scanIncr.wset(e);
        hitPairQ.enq(tuple4(e, needCuckoo, grams, bm1K));
    endrule

    Reg#(Bool)                                    scanBusy   <- mkReg(False);
    Reg#(Epoch)                                 scanEpoch  <- mkReg(0);
    Reg#(Bit#(7))                                 scanIdx    <- mkReg(0);
    Reg#(Vector#(NBitmapLanes, Bool))             scanNeed   <- mkRegU;
    Reg#(Vector#(NBitmapLanes, Maybe#(NgramOut))) scanGrams  <- mkRegU;
    Reg#(Vector#(NBitmapLanes, Bit#(18)))         scanBm1K   <- mkRegU;

    function Maybe#(Bit#(7)) nextValidHit(
        Bit#(7) start,
        Vector#(NBitmapLanes, Bool) hits,
        Vector#(NBitmapLanes, Maybe#(NgramOut)) grams
    );
        Maybe#(Bit#(7)) r = tagged Invalid;
        for (Integer i = valueOf(NBitmapLanes) - 1; i >= 0; i = i - 1) begin
            Bit#(7) idx = fromInteger(i);
            if (idx >= start && hits[i] && isValid(grams[i]))
                r = tagged Valid idx;
        end
        return r;
    endfunction

    rule startScan(!scanBusy && hitPairQ.notEmpty);
        match { .e, .need, .grams, .bm1K } = hitPairQ.first; hitPairQ.deq;
        scanEpoch <= e;
        scanNeed  <= need;
        scanGrams <= grams;
        scanBm1K  <= bm1K;
        scanIdx   <= 0;
        scanBusy  <= True;
    endrule

    // 4-wide: four static priority-selects pick the next ≤NBloomLanes valid
    // hits from scanIdx forward (no dynamic-index packing).  Build one lane per
    // selected index.  Fewer than NBloomLanes selected ⇒ batch exhausted.
    function Maybe#(BloomReq) laneOf(Maybe#(Bit#(7)) mi);
        if (mi matches tagged Valid .idx) begin
            let g = validValue(scanGrams[idx]);
            Bit#(32) key18 = zeroExtend(makeKey18(g));
            return tagged Valid mkBloomReq(
                key18, g.gram[23:0], scanBm1K[idx], g.anchor,
                payTotalLen[scanEpoch], scanEpoch, payOff, True);
        end else
            return tagged Invalid;
    endfunction
    function Bit#(7) nextStart(Maybe#(Bit#(7)) mi) =
        (mi matches tagged Valid .v ? v + 1 : fromInteger(valueOf(NBitmapLanes)));

    rule doScan(scanBusy);
        Maybe#(Bit#(7)) i0 = nextValidHit(scanIdx,        scanNeed, scanGrams);
        Maybe#(Bit#(7)) i1 = nextValidHit(nextStart(i0),  scanNeed, scanGrams);
        Maybe#(Bit#(7)) i2 = nextValidHit(nextStart(i1),  scanNeed, scanGrams);
        Maybe#(Bit#(7)) i3 = nextValidHit(nextStart(i2),  scanNeed, scanGrams);

        BloomReq4 reqs = newVector;
        reqs[0] = laneOf(i0); reqs[1] = laneOf(i1);
        reqs[2] = laneOf(i2); reqs[3] = laneOf(i3);
        Bit#(3) cnt = (isValid(i0) ? 1 : 0) + (isValid(i1) ? 1 : 0)
                    + (isValid(i2) ? 1 : 0) + (isValid(i3) ? 1 : 0);

        if (cnt != 0) begin
            gram.lookupReq4(reqs);
            gramLookups <= gramLookups + zeroExtend(cnt);
            gramIncBatch.wset(tuple2(scanEpoch, cnt));
        end
        // i3 invalid ⇒ nothing past it ⇒ batch done; else advance past i3.
        if (!isValid(i3)) begin
            scanDecr.wset(scanEpoch);
            scanBusy <= False;
        end else
            scanIdx <= nextStart(i3);
    endrule

    rule countExactInputBackpressure(state == KProcess && gramRouteQ.notEmpty &&
                                     !exactMatch.canAcceptRequest);
        exactInputBlockCycles <= exactInputBlockCycles + 1;
    endrule

    // Chain results (passes) retire 1/cycle here; bloom rejects retire in bulk
    // via gram.rejectReport (consumeBloomRejects) and never enter this stream.
    rule collectGramHits(state == KProcess);
        let gr <- gram.lookupResp;
        if (gr.lastInChain)
            gramDecChain.wset(gr.epoch);
        if (gr.hit) begin
            gramHits <= gramHits + 1;
            routeIncr.wset(gr.epoch);
            gramRouteQ.enq(gr);
        end
    endrule

    rule consumeBloomRejects(state == KProcess);
        let ri <- gram.getReject;
        bloomRejects <= bloomRejects + zeroExtend(ri.count);
        gramDecRej.wset(tuple2(ri.epoch, ri.count));
    endrule

    rule routeGramResult(state == KProcess && gramRouteQ.notEmpty);
        let gr = gramRouteQ.first; gramRouteQ.deq;
        exactChecks <= exactChecks + 1;
        routeDecr.wset(gr.epoch);
        exactIncr.wset(gr.epoch);
        exactMatch.putRequest(gr.vreq, gr.payLen, gr.epoch, gr.pay_off);
    endrule

    rule drainExact(state == KProcess && exactMatch.notEmpty);
        let r <- exactMatch.getResult;
        exactDecr.wset(r.epoch);
        // Deferred end-of-payload check: the true packet length is known only at the
        // tlast beat (conformant final-beat-metadata model), and by the time a result
        // drains here the packet has been fully fed, so payTotalLen[epoch] is final.
        // A pattern whose end extends past the real payload (would have read stale
        // bytes from the reused epoch buffer) is rejected here instead of up-stream.
        Bool endOk = (r.endOff <= payTotalLen[r.epoch]);
        if (r.hit && endOk) begin
            exactHits <= exactHits + 1;
            pomChecks  <= pomChecks + 1;
            pomIncr.wset(r.epoch);
            pomPendingQ.enq(tuple2(r.epoch, PomPktMeta {
                ruleId:     r.ruleId,
                ipProto:    pktMeta.getProto(r.epoch),
                srcPort:    pktMeta.getSrcPort(r.epoch),
                dstPort:    pktMeta.getDstPort(r.epoch),
                icmpType:   pktMeta.getIcmpType(r.epoch),
                icmpCode:   pktMeta.getIcmpCode(r.epoch),
                isTcp:      pktMeta.isTcp(r.epoch),
                isUdp:      pktMeta.isUdp(r.epoch),
                isIcmp:     pktMeta.isIcmp(r.epoch),
                matchPos:   r.matchPos,
                payloadLen: payTotalLen[r.epoch]
            }));
        end else begin
            exactMisses <= exactMisses + 1;
        end
    endrule

    // Keep POM backpressure out of drainExact's firing condition.
    rule sendToPom(pomPendingQ.notEmpty);
        match { .e, .m } = pomPendingQ.first; pomPendingQ.deq;
        portMatch.putMeta(m);
        pomCtxQ.enq(PomCtx { epoch: e, pktIdx: epochPktIdx[e] });
    endrule

    rule collectPortResult(state == KProcess && portMatch.outputReady && pomCtxQ.notEmpty &&
                           prioStage.inputReady);
        let pr <- portMatch.getResult;
        let ctx = pomCtxQ.first; pomCtxQ.deq;
        if (pr.hit)
            pomHits <= pomHits + 1;
        else
            pomMisses <= pomMisses + 1;
        pomDecr.wset(ctx.epoch);
        prioStage.putCandidate(PriorityCandidate {
            epoch:  ctx.epoch,
            pktIdx: ctx.pktIdx,
            hit:    pr.hit,
            ruleId: pr.ruleId
        });
    endrule

    rule finishPriority0(state == KProcess && epochInUse[0] && epochPipeDone(0) &&
                         inFlightPom[0] == 0 && !priorityFinishSent[0]);
        prioStage.finishEpoch(0, epochPktIdx[0]);
        priorityFinishSent[0] <= True;
    endrule

    rule finishPriority1(state == KProcess && epochInUse[1] && epochPipeDone(1) &&
                         inFlightPom[1] == 0 && !priorityFinishSent[1]);
        prioStage.finishEpoch(1, epochPktIdx[1]);
        priorityFinishSent[1] <= True;
    endrule

    rule finishPriority2(state == KProcess && epochInUse[2] && epochPipeDone(2) &&
                         inFlightPom[2] == 0 && !priorityFinishSent[2]);
        prioStage.finishEpoch(2, epochPktIdx[2]);
        priorityFinishSent[2] <= True;
    endrule

    rule finishPriority3(state == KProcess && epochInUse[3] && epochPipeDone(3) &&
                         inFlightPom[3] == 0 && !priorityFinishSent[3]);
        prioStage.finishEpoch(3, epochPktIdx[3]);
        priorityFinishSent[3] <= True;
    endrule

    rule finishPriority4(state == KProcess && epochInUse[4] && epochPipeDone(4) &&
                         inFlightPom[4] == 0 && !priorityFinishSent[4]);
        prioStage.finishEpoch(4, epochPktIdx[4]);
        priorityFinishSent[4] <= True;
    endrule

    rule finishPriority5(state == KProcess && epochInUse[5] && epochPipeDone(5) &&
                         inFlightPom[5] == 0 && !priorityFinishSent[5]);
        prioStage.finishEpoch(5, epochPktIdx[5]);
        priorityFinishSent[5] <= True;
    endrule

    rule finishPriority6(state == KProcess && epochInUse[6] && epochPipeDone(6) &&
                         inFlightPom[6] == 0 && !priorityFinishSent[6]);
        prioStage.finishEpoch(6, epochPktIdx[6]);
        priorityFinishSent[6] <= True;
    endrule

    rule finishPriority7(state == KProcess && epochInUse[7] && epochPipeDone(7) &&
                         inFlightPom[7] == 0 && !priorityFinishSent[7]);
        prioStage.finishEpoch(7, epochPktIdx[7]);
        priorityFinishSent[7] <= True;
    endrule

    rule collectPriorityResult(state == KProcess && prioStage.outputReady);
        let r <- prioStage.getResult;
        priorityDone[r.epoch]       <= True;
        priorityResultHit[r.epoch]  <= r.hit;
        priorityResultRule[r.epoch] <= r.ruleId;
    endrule

    rule retireEpoch0(state == KProcess && epochInUse[0] && epochPipeDone(0) &&
                      priorityDone[0]);
        if (!priorityResultHit[0]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[0],
                                   hit: priorityResultHit[0],
                                   ruleId: priorityResultHit[0] ? priorityResultRule[0] : 0,
                                   latency: e2eLatency(0) });
        epochInUse[0] <= False;
        payTotalLen[0] <= 0;
        priorityFinishSent[0] <= False;
        priorityDone[0] <= False;
        priorityResultHit[0] <= False;
        priorityResultRule[0] <= 0;
    endrule

    rule retireEpoch1(state == KProcess && epochInUse[1] && epochPipeDone(1) &&
                      priorityDone[1]);
        if (!priorityResultHit[1]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[1],
                                   hit: priorityResultHit[1],
                                   ruleId: priorityResultHit[1] ? priorityResultRule[1] : 0,
                                   latency: e2eLatency(1) });
        epochInUse[1] <= False;
        payTotalLen[1] <= 0;
        priorityFinishSent[1] <= False;
        priorityDone[1] <= False;
        priorityResultHit[1] <= False;
        priorityResultRule[1] <= 0;
    endrule

    rule retireEpoch2(state == KProcess && epochInUse[2] && epochPipeDone(2) &&
                      priorityDone[2]);
        if (!priorityResultHit[2]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[2],
                                   hit: priorityResultHit[2],
                                   ruleId: priorityResultHit[2] ? priorityResultRule[2] : 0,
                                   latency: e2eLatency(2) });
        epochInUse[2] <= False;
        payTotalLen[2] <= 0;
        priorityFinishSent[2] <= False;
        priorityDone[2] <= False;
        priorityResultHit[2] <= False;
        priorityResultRule[2] <= 0;
    endrule

    rule retireEpoch3(state == KProcess && epochInUse[3] && epochPipeDone(3) &&
                      priorityDone[3]);
        if (!priorityResultHit[3]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[3],
                                   hit: priorityResultHit[3],
                                   ruleId: priorityResultHit[3] ? priorityResultRule[3] : 0,
                                   latency: e2eLatency(3) });
        epochInUse[3] <= False;
        payTotalLen[3] <= 0;
        priorityFinishSent[3] <= False;
        priorityDone[3] <= False;
        priorityResultHit[3] <= False;
        priorityResultRule[3] <= 0;
    endrule

    rule retireEpoch4(state == KProcess && epochInUse[4] && epochPipeDone(4) &&
                      priorityDone[4]);
        if (!priorityResultHit[4]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[4],
                                   hit: priorityResultHit[4],
                                   ruleId: priorityResultHit[4] ? priorityResultRule[4] : 0,
                                   latency: e2eLatency(4) });
        epochInUse[4] <= False;
        payTotalLen[4] <= 0;
        priorityFinishSent[4] <= False;
        priorityDone[4] <= False;
        priorityResultHit[4] <= False;
        priorityResultRule[4] <= 0;
    endrule

    rule retireEpoch5(state == KProcess && epochInUse[5] && epochPipeDone(5) &&
                      priorityDone[5]);
        if (!priorityResultHit[5]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[5],
                                   hit: priorityResultHit[5],
                                   ruleId: priorityResultHit[5] ? priorityResultRule[5] : 0,
                                   latency: e2eLatency(5) });
        epochInUse[5] <= False;
        payTotalLen[5] <= 0;
        priorityFinishSent[5] <= False;
        priorityDone[5] <= False;
        priorityResultHit[5] <= False;
        priorityResultRule[5] <= 0;
    endrule

    rule retireEpoch6(state == KProcess && epochInUse[6] && epochPipeDone(6) &&
                      priorityDone[6]);
        if (!priorityResultHit[6]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[6],
                                   hit: priorityResultHit[6],
                                   ruleId: priorityResultHit[6] ? priorityResultRule[6] : 0,
                                   latency: e2eLatency(6) });
        epochInUse[6] <= False;
        payTotalLen[6] <= 0;
        priorityFinishSent[6] <= False;
        priorityDone[6] <= False;
        priorityResultHit[6] <= False;
        priorityResultRule[6] <= 0;
    endrule

    rule retireEpoch7(state == KProcess && epochInUse[7] && epochPipeDone(7) &&
                      priorityDone[7]);
        if (!priorityResultHit[7]) noMatchPkts <= noMatchPkts + 1;
        retireQ.enq(RetireResult { pktIdx: epochPktIdx[7],
                                   hit: priorityResultHit[7],
                                   ruleId: priorityResultHit[7] ? priorityResultRule[7] : 0,
                                   latency: e2eLatency(7) });
        epochInUse[7] <= False;
        payTotalLen[7] <= 0;
        priorityFinishSent[7] <= False;
        priorityDone[7] <= False;
        priorityResultHit[7] <= False;
        priorityResultRule[7] <= 0;
    endrule

    rule writeRetiredResult(state == KProcess && retireQ.notEmpty &&
                            resultWriter.canAccept(retireQ.first.pktIdx));
        let r = retireQ.first; retireQ.deq;
        resultWriter.addResult(r.pktIdx, r.hit, r.ruleId, r.latency);
        lastRetireCyc <= timerTotal.value;
        $display("RETIRE pkt=%0d hit=%0d", r.pktIdx, r.hit);
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
        $display("STATS gramHits=%0d exactChk=%0d exactHit=%0d exactMiss=%0d pomChk=%0d pomHit=%0d pomMiss=%0d bloomRej=%0d noMatch=%0d",
                 gramHits, exactChecks, exactHits, exactMisses,
                 pomChecks, pomHits, pomMisses, bloomRejects, noMatchPkts);
    endrule

    // DEBUG watchdog: when wedged, dumps the frozen per-epoch state every 200k
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
                 metaReady, pktReader.pktReady);
        $display("  ADM: beatAvail=%0d anyFreeEpoch=%0d nextOut=%0d",
                 pktReader.beatAvailable, anyFreeEpoch, resultWriter.dbgNextOut);
    endrule

    // Free-running: no process-done / write / done phases. Once DB is loaded the
    // kernel stays in KProcess and matches packets forever.

    // Boot once out of reset: kick the DB section loader (it self-terminates at
    // DLDone after the bloom section) and reset the result reorder buffer.
    rule selfBoot(!booted && state == KIdle);
        booted <= True;
        resultWriter.configure;
        dataLoader.startLoad(0);   // dbBytes advisory; FSM ends at DLDone
        timerTotal.markStart;
        timerDb.markStart;
        state <= KInit;
    endrule

    rule doInit(state == KInit && dataLoader.loadDone);
        $display("KM init done");
        timerDb.markDone;
        timerPkt.markStart;
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
