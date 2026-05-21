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

typedef struct {
    Bit#(64) addr;
    Bit#(64) bytes;
} MemReq deriving (Bits, Eq);

interface MemPortIfc;
    method ActionValue#(MemReq) readReq;
    method ActionValue#(MemReq) writeReq;
    method ActionValue#(Bit#(512)) writeWord;
    method Action readWord(Bit#(512) word);
endinterface

interface KernelMainIfc;
    method Action start(Bit#(32) pktCount, Bit#(32) dbBytes,
                        Bit#(64) dbBase, Bit#(64) pktBase, Bit#(64) resultBase);
    method ActionValue#(Bool) done;
    interface Vector#(3, MemPortIfc) mem;
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
    DataLoaderIfc         dataLoader   <- mkDataLoader(bm0_s1, bm0_s2, bm1, gram, patternTable, portMatch, prioStage);
    PacketReaderIfc       pktReader    <- mkPacketReader;
    ResultWriterIfc       resultWriter <- mkResultWriter;

    CycleCounterIfc timerDb    <- mkCycleCounter;
    CycleCounterIfc timerPkt   <- mkCycleCounter;
    CycleCounterIfc timerTotal <- mkCycleCounter;

    Vector#(3, FIFO#(MemReq))     rdReqQs  <- replicateM(mkFIFO);
    Vector#(3, FIFO#(MemReq))     wrReqQs  <- replicateM(mkFIFO);
    Vector#(3, FIFO#(Bit#(512)))  wrWordQs <- replicateM(mkFIFO);
    Vector#(3, FIFOF#(Bit#(512))) rdWordQs <- replicateM(mkSizedFIFOF(16));

    FIFO#(Bool) doneQ <- mkFIFO;
    Reg#(KState) state <- mkReg(KIdle);

    Reg#(Bit#(32)) rPktCount   <- mkRegU;
    Reg#(Bit#(64)) rPktBase    <- mkRegU;
    Reg#(Bit#(64)) rResultBase <- mkRegU;

    Reg#(Bit#(6))   payOff       <- mkReg(0);
    Reg#(Epoch)     curEpoch     <- mkReg(0);
    Reg#(Bit#(32))  curPktIdx    <- mkReg(0);
    Reg#(Bool)      metaReady    <- mkReg(False);

    Vector#(NEpoch, Reg#(Bool))     epochInUse    <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bit#(32))) epochPktIdx    <- replicateM(mkReg(0));
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
    RWire#(Epoch) gramIncr   <- mkRWire;
    RWire#(Epoch) gramDecr   <- mkRWire;
    RWire#(Epoch) pomIncr    <- mkRWire;
    RWire#(Epoch) pomDecr    <- mkRWire;

    // Exact hits are staged before POM so exactMatch draining does not inherit
    // POM BRAM/FIFO readiness as an implicit condition.
    FIFOF#(Tuple2#(Epoch, PomPktMeta))   pomPendingQ <- mkSizedFIFOF(32);
    FIFOF#(PomCtx)                      pomCtxQ     <- mkSizedFIFOF(32);
    FIFOF#(RetireResult)                retireQ     <- mkSizedFIFOF(8);

    // E2E span tracking includes queued inter-stage work.
    //   gramSideQ : bitmap.lookup → pairBitmapResults (waits for bm results)
    //   hitPairQ  : pairBitmapResults → startScan (bitmap → gram intake)
    //   gramRouteQ: collectGramHits → routeGramResult (gram → exact intake)
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
    Reg#(Bit#(32)) exactCycles        <- mkReg(0);
    Reg#(Bit#(32)) pomCycles          <- mkReg(0);
    Reg#(Bit#(32)) resultWriterCycles <- mkReg(0);

    // Per-module wall-clock spans, including stalls and queueing.
    E2ESpanIfc dataLoaderSpan   <- mkE2ESpan;
    E2ESpanIfc packetReaderSpan <- mkE2ESpan;
    E2ESpanIfc payloadFeedSpan  <- mkE2ESpan;
    E2ESpanIfc ngramSpan        <- mkE2ESpan;
    E2ESpanIfc bitmapSpan       <- mkE2ESpan;
    E2ESpanIfc gramSpan         <- mkE2ESpan;
    E2ESpanIfc exactSpan        <- mkE2ESpan;
    E2ESpanIfc pomSpan          <- mkE2ESpan;
    E2ESpanIfc resultWriterSpan <- mkE2ESpan;

    Reg#(Bit#(32)) gramsExtracted     <- mkReg(0);
    Reg#(Bit#(32)) bitmapPassed       <- mkReg(0);
    Reg#(Bit#(32)) gramLookups        <- mkReg(0);
    Reg#(Bit#(32)) gramHits           <- mkReg(0);
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

    rule dbReadReq;
        let {addr, bytes} <- dataLoader.readReq;
        rdReqQs[0].enq(MemReq { addr: addr, bytes: bytes });
    endrule
    rule dbReadWord;
        dataLoader.readWord(rdWordQs[0].first);
        rdWordQs[0].deq;
    endrule

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
    addRules(mkCounterUpdate(inFlightGram,   gramIncr,   gramDecr));
    addRules(mkCounterUpdate(inFlightPom,    pomIncr,    pomDecr));
    addRules(mkCounterUpdate(inFlightBitmap, bitmapIncr, bitmapDecr));
    addRules(mkCounterUpdate(inFlightScan,   scanIncr,   scanDecr));

    rule pktReadReq;
        let {addr, bytes} <- pktReader.readReq;
        rdReqQs[1].enq(MemReq { addr: addr, bytes: bytes });
    endrule
    rule pktReadWord;
        pktReader.readWord(rdWordQs[1].first);
        rdWordQs[1].deq;
    endrule

    rule resWriteReq;
        let {addr, bytes} <- resultWriter.writeReq;
        wrReqQs[2].enq(MemReq { addr: addr, bytes: bytes });
    endrule
    rule resWriteWord;
        let w <- resultWriter.writeWord;
        wrWordQs[2].enq(w);
    endrule

    rule countModuleCycles(
        (state == KInit && !dataLoader.loadDone) ||
        (state == KProcess && !pktReader.allDone) ||
        (state == KDone && !resultWriter.writeDone)
    );
        Bit#(32) now = timerTotal.value;

        if (state == KInit && !dataLoader.loadDone) begin
            dataLoaderCycles <= dataLoaderCycles + 1;
            dataLoaderSpan.mark(now);
        end

        if (state == KProcess && !pktReader.allDone) begin
            // E2E marks include inter-stage queues so spans stay ordered.
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
            if (exactInner) exactCycles <= exactCycles + 1;
            if (exactInner || gramRouteQ.notEmpty)
                exactSpan.mark(now);
            if (pomInner) pomCycles <= pomCycles + 1;
            if (pomInner || pomPendingQ.notEmpty || pomCtxQ.notEmpty)
                pomSpan.mark(now);
        end

        if (state == KDone && !resultWriter.writeDone) begin
            resultWriterCycles <= resultWriterCycles + 1;
            resultWriterSpan.mark(now);
        end
    endrule

    rule countGaps(state == KProcess && !pktReader.allDone);
        if (pktReader.pktDone)
            gapBackend <= gapBackend + 1;
        else if (pktReader.feedAwaitingLine)
            gapHbm <= gapHbm + 1;
        else if (pktReader.pktReady && !metaReady)
            gapMetaWait <= gapMetaWait + 1;
        else if (pktReader.busy && !pktReader.pktReady)
            gapReaderOther <= gapReaderOther + 1;
    endrule

    rule countReaderBreakdown(state == KProcess && !pktReader.allDone);
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
        if (pktReader.pktReady && !metaReady && pktReader.metaAvailable && !anyFreeEpoch)
            epochFullCycles <= epochFullCycles + 1;
        if (retireQ.notEmpty && !resultWriter.canAccept(retireQ.first.pktIdx))
            resultAcceptBlockCycles <= resultAcceptBlockCycles + 1;
    endrule

    rule latchMeta(state == KProcess && !metaReady && pktReader.metaAvailable && anyFreeEpoch);
        let m <- pktReader.nextMeta;
        Epoch e = chooseFreeEpoch;
        pktMeta.put(e, m.meta);
        curEpoch       <= e;
        curPktIdx      <= m.pktIdx;
        epochInUse[e]  <= True;
        epochPktIdx[e] <= m.pktIdx;
        payTotalLen[e] <= m.payloadLen;
        feedDone[e]    <= (m.payloadLen == 0);
        metaReady      <= (m.payloadLen != 0);
    endrule

    rule feedPayloadWord(state == KProcess && pktReader.pktReady && metaReady);
        Bit#(512) word = pktReader.getLine;
        Bit#(7)   cnt  = pktReader.lineValidBytes;
        Bool      last = pktReader.lineIsLast;

        if (awaitingFirstFeed) begin
            Bit#(32) now = timerTotal.value;
            gapNextStart      <= gapNextStart + (now - lastNextCycle);
            awaitingFirstFeed <= False;
        end

        Epoch e = curEpoch;

        payOff <= 0;
        payloadFeedCycles <= payloadFeedCycles + 1;
        payloadFeedSpan.mark(timerTotal.value);

        ngram.putBytes(word, 0, cnt, last, e);
        exactMatch.putPayloadWord(word, last, e);
        ngramIncr.wset(e);

        if (last && pktReader.nextAfterLineReady && anyFreeEpoch) begin
            let m <- pktReader.advanceLineAndStartNextMeta;
            Epoch ne = chooseFreeEpoch;
            pktMeta.put(ne, m.meta);
            curEpoch       <= ne;
            curPktIdx      <= m.pktIdx;
            epochInUse[ne] <= True;
            epochPktIdx[ne] <= m.pktIdx;
            payTotalLen[ne] <= m.payloadLen;
            for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
                Epoch ie = fromInteger(i);
                if (ie == e)
                    feedDone[i] <= True;
                else if (ie == ne)
                    feedDone[i] <= (m.payloadLen == 0);
            end
            metaReady      <= (m.payloadLen != 0);
        end else begin
            pktReader.advanceLine;
            if (last)
                metaReady <= False;
        end

        if (last && !(pktReader.nextAfterLineReady && anyFreeEpoch)) begin
            feedDone[e] <= True;
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
               inFlightExact[e] == 0;
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

    rule doScan(scanBusy);
        case (nextValidHit(scanIdx, scanNeed, scanGrams)) matches
            tagged Valid .idx: begin
                let g = validValue(scanGrams[idx]);
                Bit#(32) key18 = zeroExtend(makeKey18(g));
                gram.lookupReq(key18, g.gram[23:0], scanBm1K[idx], g.anchor,
                               payTotalLen[scanEpoch], scanEpoch, payOff, True);
                gramLookups <= gramLookups + 1;
                gramIncr.wset(scanEpoch);
                scanIdx <= idx + 1;
            end
            tagged Invalid: begin
                scanDecr.wset(scanEpoch);
                scanBusy <= False;
            end
        endcase
    endrule

    rule countExactInputBackpressure(state == KProcess && gramRouteQ.notEmpty &&
                                     !exactMatch.canAcceptRequest);
        exactInputBlockCycles <= exactInputBlockCycles + 1;
    endrule

    rule collectGramHits(state == KProcess);
        let gr <- gram.lookupResp;
        if (gr.lastInChain)
            gramDecr.wset(gr.epoch);
        if (gr.hit) begin
            gramHits <= gramHits + 1;
            inFlightRoute[gr.epoch] <= inFlightRoute[gr.epoch] + 1;
            gramRouteQ.enq(gr);
        end
    endrule

    rule routeGramResult(state == KProcess && gramRouteQ.notEmpty);
        let gr = gramRouteQ.first; gramRouteQ.deq;
        exactChecks <= exactChecks + 1;
        inFlightRoute[gr.epoch] <= inFlightRoute[gr.epoch] - 1;
        inFlightExact[gr.epoch] <= inFlightExact[gr.epoch] + 1;
        exactMatch.putRequest(gr.vreq, gr.payLen, gr.epoch, gr.pay_off);
    endrule

    rule drainExact(state == KProcess && exactMatch.notEmpty);
        let r <- exactMatch.getResult;
        inFlightExact[r.epoch] <= inFlightExact[r.epoch] - 1;
        if (r.hit) begin
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
                payloadLen: r.payLen
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
                                   ruleId: priorityResultHit[0] ? priorityResultRule[0] : 0 });
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
                                   ruleId: priorityResultHit[1] ? priorityResultRule[1] : 0 });
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
                                   ruleId: priorityResultHit[2] ? priorityResultRule[2] : 0 });
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
                                   ruleId: priorityResultHit[3] ? priorityResultRule[3] : 0 });
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
                                   ruleId: priorityResultHit[4] ? priorityResultRule[4] : 0 });
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
                                   ruleId: priorityResultHit[5] ? priorityResultRule[5] : 0 });
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
                                   ruleId: priorityResultHit[6] ? priorityResultRule[6] : 0 });
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
                                   ruleId: priorityResultHit[7] ? priorityResultRule[7] : 0 });
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
        resultWriter.addResult(r.pktIdx, r.hit, r.ruleId);
    endrule

    rule doProcDone(state == KProcess && pktReader.allDone &&
                    !pktReader.metaAvailable && !metaReady &&
                    !anyEpochInUse &&
                    !retireQ.notEmpty);
        $display("KM process done");
        timerPkt.markDone;
        timerTotal.markDone;
        state <= KWritePrep;
    endrule

    rule doInit(state == KInit && dataLoader.loadDone);
        $display("KM init done");
        timerDb.markDone;
        timerPkt.markStart;
        pktReader.startRead(rPktBase, rPktCount);
        state <= KProcess;
    endrule

    rule captureWriteSummary(state == KWritePrep);
        let summary = ResultSummary {
            dbCycles:           timerDb.elapsed,
            pktCycles:          timerPkt.elapsed,
            totalCycles:        timerTotal.elapsed,
            dataLoaderCycles:   dataLoaderCycles,
            packetReaderCycles: packetReaderCycles,
            payloadFeedCycles:  payloadFeedCycles,
            ngramCycles:        ngramCycles,
            bitmapCycles:       bitmapCycles,
            gramCycles:         gramCycles,
            exactCycles:        exactCycles,
            pomCycles:          pomCycles,
            resultWriterCycles: resultWriterCycles,
            gramsExtracted:     gramsExtracted,
            bitmapPassed:       bitmapPassed,
            gramLookups:        gramLookups,
            gramHits:           gramHits,
            exactChecks:        exactChecks,
            exactHits:          exactHits,
            exactMisses:        exactMisses,
            pomChecks:          pomChecks,
            pomHits:            pomHits,
            pomMisses:          pomMisses,
            noMatchPkts:        noMatchPkts,
            stage2Checked:      stage2Checked,
            stage2Passed:       stage2Passed,
            gapBackend:         gapBackend,
            gapHbm:             gapHbm,
            gapReaderOther:     gapReaderOther,
            gapMetaWait:        gapMetaWait,
            gapNextStart:       gapNextStart,
            readerDescCycles:   readerDescCycles,
            readerStartCycles:  readerStartCycles,
            readerFirstLineWaitCycles: readerFirstLineWaitCycles,
            readerRespCycles:   readerRespCycles,
            epochFullCycles:    epochFullCycles,
            resultAcceptBlockCycles: resultAcceptBlockCycles,
            exactInputBlockCycles: exactInputBlockCycles,
            dataLoaderE2E:      dataLoaderSpan.elapsed,
            packetReaderE2E:    packetReaderSpan.elapsed,
            payloadFeedE2E:     payloadFeedSpan.elapsed,
            ngramE2E:           ngramSpan.elapsed,
            bitmapE2E:          bitmapSpan.elapsed,
            gramE2E:            gramSpan.elapsed,
            exactE2E:           exactSpan.elapsed,
            pomE2E:             pomSpan.elapsed,
            resultWriterE2E:    resultWriterSpan.elapsed
        };
        resultSummary <= summary;
        state <= KWrite;
    endrule

    rule doWrite(state == KWrite);
        $display("KM write start");
        resultWriter.startWrite(resultSummary);
        state <= KDone;
    endrule

    rule doDone(state == KDone && resultWriter.writeDone);
        $display("KM done");
        doneQ.enq(True);
        state <= KIdle;
    endrule

    Vector#(3, MemPortIfc) mem_;
    for (Integer i = 0; i < 3; i = i + 1) begin
        mem_[i] = interface MemPortIfc;
            method ActionValue#(MemReq) readReq;
                let r = rdReqQs[i].first; rdReqQs[i].deq; return r;
            endmethod
            method ActionValue#(MemReq) writeReq;
                let r = wrReqQs[i].first; wrReqQs[i].deq; return r;
            endmethod
            method ActionValue#(Bit#(512)) writeWord;
                let w = wrWordQs[i].first; wrWordQs[i].deq; return w;
            endmethod
            method Action readWord(Bit#(512) word);
                rdWordQs[i].enq(word);
            endmethod
        endinterface;
    end

    method Action start(Bit#(32) pktCount, Bit#(32) dbBytes,
                        Bit#(64) dbBase, Bit#(64) pktBase, Bit#(64) resultBase)
            if (state == KIdle);
        rPktCount   <= pktCount;
        rPktBase    <= pktBase;
        rResultBase <= resultBase;
        dataLoaderCycles   <= 0;
        packetReaderCycles <= 0;
        payloadFeedCycles  <= 0;
        ngramCycles        <= 0;
        bitmapCycles       <= 0;
        gramCycles         <= 0;
        exactCycles        <= 0;
        pomCycles          <= 0;
        resultWriterCycles <= 0;
        gramsExtracted     <= 0;
        bitmapPassed       <= 0;
        gramLookups        <= 0;
        gramHits           <= 0;
        exactChecks        <= 0;
        exactHits          <= 0;
        exactMisses        <= 0;
        pomChecks          <= 0;
        pomHits            <= 0;
        pomMisses          <= 0;
        noMatchPkts        <= 0;
        stage2Checked      <= 0;
        stage2Passed       <= 0;
        gapBackend         <= 0;
        gapHbm             <= 0;
        gapReaderOther     <= 0;
        gapMetaWait        <= 0;
        gapNextStart       <= 0;
        readerDescCycles   <= 0;
        readerStartCycles  <= 0;
        readerFirstLineWaitCycles <= 0;
        readerRespCycles   <= 0;
        epochFullCycles    <= 0;
        resultAcceptBlockCycles <= 0;
        exactInputBlockCycles <= 0;
        lastNextCycle      <= 0;
        awaitingFirstFeed  <= False;
        resultSummary      <= unpack(0);
        dataLoaderSpan.reset_;
        packetReaderSpan.reset_;
        payloadFeedSpan.reset_;
        ngramSpan.reset_;
        bitmapSpan.reset_;
        gramSpan.reset_;
        exactSpan.reset_;
        pomSpan.reset_;
        resultWriterSpan.reset_;
        payOff             <= 0;
        metaReady          <= False;
        curEpoch           <= 0;
        curPktIdx          <= 0;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1) begin
            epochInUse[i]    <= False;
            epochPktIdx[i]    <= 0;
            payTotalLen[i]    <= 0;
            feedDone[i]       <= False;
            priorityFinishSent[i] <= False;
            priorityDone[i]       <= False;
            priorityResultHit[i]  <= False;
            priorityResultRule[i] <= 0;
            inFlightNgram[i]  <= 0;
            inFlightBitmap[i] <= 0;
            inFlightScan[i]   <= 0;
            inFlightGram[i]   <= 0;
            inFlightRoute[i]  <= 0;
            inFlightExact[i]  <= 0;
            inFlightPom[i]    <= 0;
            hasPrev[i]        <= False;
            tailReady[i]      <= False;
        end
        resultWriter.configure(resultBase, pktCount);
        timerTotal.markStart;
        timerDb.markStart;
        dataLoader.startLoad(dbBase, dbBytes);
        state <= KInit;
    endmethod

    method ActionValue#(Bool) done;
        let d = doneQ.first; doneQ.deq; return d;
    endmethod

    interface mem = mem_;
endmodule

endpackage
