package KernelMain;

import FIFO::*;
import FIFOF::*;
import ConfigReg::*;
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
import AxiStream::*;
import DbStreamLoader::*;
import ResultStreamWriter::*;
import PacketStreamReader::*;

interface KernelMainIfc;
    // Free-running (ap_ctrl_none): no start/done handshake. The kernel boots,
    // loads the rule DB off s_axis_db, then processes packets forever.
    interface AxiStreamSlavePinsIfc#(512) s_axis_db;
    interface AxiStreamSlaveUserPinsIfc#(512, 128) s_axis_pkt;
    interface AxiStreamMasterPinsIfc#(32) m_axis_result;
endinterface

typedef 8 NEpoch;
typedef Bit#(3) Epoch;

typedef enum { KIdle, KInit, KProcess } KState deriving (Bits, Eq, FShow);

typedef struct {
    Epoch    epoch;
    Bit#(32) pktIdx;
} PomCtx deriving (Bits, Eq, FShow);

typedef struct {
    Bit#(32) pktIdx;
    Bool     hit;
    Bit#(16) ruleId;
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

    Reg#(Bit#(6))   payOff       <- mkReg(0);
    Reg#(Epoch)     curEpoch     <- mkReg(0);
    Reg#(Bit#(32))  curPktIdx    <- mkReg(0);
    Reg#(Bool)      metaReady    <- mkReg(False);

    Vector#(NEpoch, Reg#(Bool))     epochInUse    <- replicateM(mkReg(False));
    Vector#(NEpoch, Reg#(Bit#(32))) epochPktIdx    <- replicateM(mkReg(0));
    Vector#(NEpoch, Reg#(Bit#(32))) admitCyc       <- replicateM(mkReg(0));
    Reg#(Bit#(32)) wdLast <- mkReg(0);  // DEBUG watchdog last-dump cycle
    // Total process-cycle measurement (no per-packet overlap): span from the
    // first packet admitted to the last packet retired, emitted as a footer beat.
    Reg#(Bool)     procStarted  <- mkReg(False);
    Reg#(Bit#(32)) firstAdmitCyc <- mkReg(0);
    Reg#(Bit#(32)) lastRetireCyc <- mkReg(0);
    Reg#(Bit#(32)) idleCnt       <- mkReg(0);
    Reg#(Bool)     footerDone    <- mkReg(False);
    // admit->now latency for epoch e, saturated to 15 bits.
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
    FIFOF#(Tuple4#(Epoch,
                   Vector#(NBitmapLanes, Maybe#(NgramOut)),
                   Vector#(NBitmapLanes, Bool),
                   Vector#(NBitmapLanes, Bit#(18))))        gramSideQ  <- mkSizedFIFOF(16);
    FIFOF#(Tuple4#(Epoch,
                   Vector#(NBitmapLanes, Bool),
                   Vector#(NBitmapLanes, Maybe#(NgramOut)),
                   Vector#(NBitmapLanes, Bit#(18))))        hitPairQ   <- mkSizedFIFOF(16);
    FIFOF#(GramResult)                                      gramRouteQ <- mkSizedFIFOF(16);

    // Live match telemetry (read by the STATS $display).
    Reg#(Bit#(32)) bitmapPassed       <- mkReg(0);
    Reg#(Bit#(32)) gramHits           <- mkReg(0);
    Reg#(Bit#(32)) bloomRejects       <- mkReg(0);
    Reg#(Bit#(32)) exactChecks        <- mkReg(0);
    Reg#(Bit#(32)) exactHits          <- mkReg(0);
    Reg#(Bit#(32)) exactMisses        <- mkReg(0);
    Reg#(Bit#(32)) pomChecks          <- mkReg(0);
    Reg#(Bit#(32)) pomHits            <- mkReg(0);
    Reg#(Bit#(32)) pomMisses          <- mkReg(0);
    Reg#(Bit#(32)) noMatchPkts        <- mkReg(0);
    Reg#(Bit#(32)) stage2Passed       <- mkReg(0);

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
        feedDone[e]    <= False;
        if (!procStarted) begin     // first packet admitted -> start proc clock
            procStarted   <= True;
            firstAdmitCyc <= timerTotal.value;
        end
    endrule

    // feedBeat: stream the armed packet's beats into ngram/exact; capture the
    // 5-tuple + final length on the last beat. No resultWriter read -> no cycle.
    // The n-gram front end is NBitmapLanes bytes wide, which is narrower than a
    // 512-bit beat, so each beat is fed as ChunksPerBeat consecutive slices.
    // The beat is retired (advanceBeat) and its end-of-packet side effects are
    // applied only on the final slice; the payload word goes to ExactMatch once,
    // on the first slice.
    Integer chunksPerBeat = 64 / valueOf(NBitmapLanes);
    Reg#(Bit#(3)) feedChunk <- mkReg(0);

    rule feedBeat(state == KProcess && metaReady && pktReader.beatAvailable);
        let bt = pktReader.beat;

        Epoch e = curEpoch;

        Bit#(7) laneW  = fromInteger(valueOf(NBitmapLanes));
        Bit#(7) start  = zeroExtend(feedChunk) * laneW;
        Bit#(7) remain = (bt.validBytes > start) ? (bt.validBytes - start) : 0;
        Bit#(7) cnt    = (remain > laneW) ? laneW : remain;
        Bool lastChunk = ((start + cnt) >= bt.validBytes)
                         || (feedChunk == fromInteger(chunksPerBeat - 1));

        // tlast rides the final slice so the extracter flushes its carry there.
        ngram.putBytes(bt.word, start, cnt, bt.last && lastChunk, e);
        ngramIncr.wset(e);

        if (feedChunk == 0)
            exactMatch.putPayloadWord(bt.word, bt.last, e);

        if (lastChunk) begin
            pktReader.advanceBeat;
            feedChunk      <= 0;
            payTotalLen[e] <= bt.payloadLen;   // running length; final on last beat

            if (bt.last) begin
                pktMeta.put(e, bt.meta);
                feedDone[e] <= True;
                metaReady   <= False;
            end
        end else begin
            feedChunk <= feedChunk + 1;
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
    endfunction

    Vector#(NEpoch, Reg#(Bool)) pipeDoneR <- replicateM(mkConfigReg(False));
    (* fire_when_enabled, no_implicit_conditions *)
    rule regPipeDone;
        for (Integer i = 0; i < valueOf(NEpoch); i = i + 1)
            pipeDoneR[i] <= epochPipeDone(fromInteger(i));
    endrule
    function Bool epochDoneR(Epoch e) = pipeDoneR[e] && feedDone[e];

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
        stage2Passed  <= stage2Passed  + bm0S2AndBm1;
        bitmapDecr.wset(e);
        scanIncr.wset(e);
        hitPairQ.enq(tuple4(e, needCuckoo, grams, bm1K));
    endrule

    Reg#(Bool)                                 scanBusy    <- mkReg(False);
    Reg#(Epoch)                                scanEpoch   <- mkReg(0);
    Reg#(Bit#(7))                              scanIdx     <- mkReg(0);   // rank cursor
    Reg#(Vector#(NBitmapLanes, Bool))          scanSel     <- mkRegU;     // lane is a real need-lane
    Reg#(Vector#(NBitmapLanes, Bit#(7)))       scanRank    <- mkRegU;     // exclusive prefix rank
    Reg#(Vector#(NBitmapLanes, NgramOut))      scanGram    <- mkRegU;     // unwrapped gram per lane
    Reg#(Vector#(NBitmapLanes, Bit#(18)))      scanBm1K    <- mkRegU;
    Reg#(Bit#(7))                              packedCount <- mkRegU;     // number of need-lanes
    FIFOF#(BloomReq4)                          bloomFeedQ  <- mkFIFOF;

    rule startScan(!scanBusy && hitPairQ.notEmpty);
        match { .e, .need, .grams, .bm1K } = hitPairQ.first; hitPairQ.deq;

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

        scanSel     <= sel;
        scanRank    <= rankV;
        scanGram    <= gUn;
        scanBm1K    <= bm1K;
        packedCount <= zeroExtend(pack(countOnes(selBits)));
        scanEpoch   <= e;
        scanIdx     <= 0;
        scanBusy    <= True;
    endrule

    rule doScan(scanBusy);
        Bit#(7) n = packedCount;
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
                if (scanSel[i] && scanRank[i][6:2] == scanIdx[6:2]
                               && scanRank[i][1:0] == fromInteger(k)) begin
                    g     = scanGram[i];
                    kk    = scanBm1K[i];
                    found = True;
                end
            Bit#(32) key18 = zeroExtend(makeKey18(g));
            let req = mkBloomReq(key18, g.gram[23:0], kk, g.anchor,
                                 0, scanEpoch, payOff, True);
            return found ? tagged Valid req : tagged Invalid;
        endfunction

        BloomReq4 reqs = newVector;
        for (Integer k = 0; k < 4; k = k + 1) reqs[k] = laneForRank(k);
        Bit#(3) cnt = 0;
        for (Integer k = 0; k < 4; k = k + 1) if (isValid(reqs[k])) cnt = cnt + 1;

        if (cnt != 0) begin
            bloomFeedQ.enq(reqs);
            gramIncBatch.wset(tuple2(scanEpoch, cnt));
        end
        if (scanIdx + 4 >= n) begin
            scanDecr.wset(scanEpoch);
            scanBusy <= False;
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

    FIFOF#(Tuple4#(Epoch, Bit#(16), Bit#(32), Bit#(32))) pomHoldQ <- mkSizedFIFOF(64);

    rule drainExact(state == KProcess && exactMatch.notEmpty);
        let r <- exactMatch.getResult;
        exactDecr.wset(r.epoch);
        if (r.hit) begin
            // Count it as in-flight POM work from here: while it sits in pomHoldQ it
            // is in neither inFlightExact nor inFlightPom otherwise, and epochPipeDone
            // would finalize the epoch and drop the match.
            pomIncr.wset(r.epoch);
            pomHoldQ.enq(tuple4(r.epoch, r.ruleId, r.matchPos, r.endOff));
        end else begin
            exactMisses <= exactMisses + 1;
        end
    endrule

    FIFOF#(Tuple3#(Epoch, Bit#(32), PomPktMeta)) pomRelQ <- mkFIFOF;

    rule releasePomCandidate(state == KProcess && feedDone[tpl_1(pomHoldQ.first)]);
        match { .e, .rid, .mpos, .eoff } = pomHoldQ.first; pomHoldQ.deq;
        pomRelQ.enq(tuple3(e, eoff, PomPktMeta {
                ruleId:     rid,
                ipProto:    pktMeta.getProto(e),
                srcPort:    pktMeta.getSrcPort(e),
                dstPort:    pktMeta.getDstPort(e),
                icmpType:   pktMeta.getIcmpType(e),
                icmpCode:   pktMeta.getIcmpCode(e),
                isTcp:      pktMeta.isTcp(e),
                isUdp:      pktMeta.isUdp(e),
                isIcmp:     pktMeta.isIcmp(e),
                matchPos:   mpos,
                payloadLen: payTotalLen[e]
            }));
    endrule

    rule checkPomEnd(state == KProcess);
        match { .e, .eoff, .m } = pomRelQ.first; pomRelQ.deq;
        if (eoff <= m.payloadLen) begin
            exactHits <= exactHits + 1;
            pomChecks <= pomChecks + 1;
            pomPendingQ.enq(tuple2(e, m));
        end else begin
            // Rejected here, so it never reaches collectPortResult's pomDecr.
            pomDecr.wset(e);
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

    rule finishPriority0(state == KProcess && epochInUse[0] && epochDoneR(0) &&
                         inFlightPom[0] == 0 && !priorityFinishSent[0]);
        prioStage.finishEpoch(0, epochPktIdx[0]);
        priorityFinishSent[0] <= True;
    endrule

    rule finishPriority1(state == KProcess && epochInUse[1] && epochDoneR(1) &&
                         inFlightPom[1] == 0 && !priorityFinishSent[1]);
        prioStage.finishEpoch(1, epochPktIdx[1]);
        priorityFinishSent[1] <= True;
    endrule

    rule finishPriority2(state == KProcess && epochInUse[2] && epochDoneR(2) &&
                         inFlightPom[2] == 0 && !priorityFinishSent[2]);
        prioStage.finishEpoch(2, epochPktIdx[2]);
        priorityFinishSent[2] <= True;
    endrule

    rule finishPriority3(state == KProcess && epochInUse[3] && epochDoneR(3) &&
                         inFlightPom[3] == 0 && !priorityFinishSent[3]);
        prioStage.finishEpoch(3, epochPktIdx[3]);
        priorityFinishSent[3] <= True;
    endrule

    rule finishPriority4(state == KProcess && epochInUse[4] && epochDoneR(4) &&
                         inFlightPom[4] == 0 && !priorityFinishSent[4]);
        prioStage.finishEpoch(4, epochPktIdx[4]);
        priorityFinishSent[4] <= True;
    endrule

    rule finishPriority5(state == KProcess && epochInUse[5] && epochDoneR(5) &&
                         inFlightPom[5] == 0 && !priorityFinishSent[5]);
        prioStage.finishEpoch(5, epochPktIdx[5]);
        priorityFinishSent[5] <= True;
    endrule

    rule finishPriority6(state == KProcess && epochInUse[6] && epochDoneR(6) &&
                         inFlightPom[6] == 0 && !priorityFinishSent[6]);
        prioStage.finishEpoch(6, epochPktIdx[6]);
        priorityFinishSent[6] <= True;
    endrule

    rule finishPriority7(state == KProcess && epochInUse[7] && epochDoneR(7) &&
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

    rule retireEpoch0(state == KProcess && epochInUse[0] && epochDoneR(0) &&
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

    rule retireEpoch1(state == KProcess && epochInUse[1] && epochDoneR(1) &&
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

    rule retireEpoch2(state == KProcess && epochInUse[2] && epochDoneR(2) &&
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

    rule retireEpoch3(state == KProcess && epochInUse[3] && epochDoneR(3) &&
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

    rule retireEpoch4(state == KProcess && epochInUse[4] && epochDoneR(4) &&
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

    rule retireEpoch5(state == KProcess && epochInUse[5] && epochDoneR(5) &&
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

    rule retireEpoch6(state == KProcess && epochInUse[6] && epochDoneR(6) &&
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

    rule retireEpoch7(state == KProcess && epochInUse[7] && epochDoneR(7) &&
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
                 metaReady, pktReader.beatAvailable);
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
