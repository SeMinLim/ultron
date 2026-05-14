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

typedef enum { KIdle, KInit, KProcess, KWritePrep, KWrite, KDone } KState deriving (Bits, Eq, FShow);

module mkKernelMain(KernelMainIfc);

    ExactPatternTableIfc  patternTable <- mkExactPatternTable;
    BitmapUramIfc         bm0_s1       <- mkBitmapUram;
    BitmapUramIfc         bm0_s2       <- mkBitmapUram;
    BitmapUramIfc         bm1          <- mkBitmapUram;
    GramMatcherIfc        gram         <- mkGramMatcher;
    NgramExtracterIfc     ngram        <- mkNgramExtracter;
    PacketMetaIfc         pktMeta      <- mkPacketMeta;
    ExactMatchIfc         exactMatch   <- mkExactMatch(patternTable);
    PortOffsetMatcherIfc  portMatch    <- mkPortOffsetMatcher;
    DataLoaderIfc         dataLoader   <- mkDataLoader(bm0_s1, bm0_s2, bm1, gram, patternTable, portMatch);
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

    Reg#(Bit#(32))  payTotalLen  <- mkReg(0);
    Reg#(Bit#(6))   payOff       <- mkReg(0);
    Reg#(Bit#(1))   payEpoch     <- mkReg(0);
    Reg#(Bit#(1))   payWriteEpoch <- mkRegU;
    Reg#(Bool)      metaReady    <- mkReg(False);

    Reg#(Bool)               pktHitSent <- mkReg(False);
    Reg#(Maybe#(PomPktMeta)) pomPending  <- mkReg(tagged Invalid);

    Reg#(Bit#(32)) dataLoaderCycles   <- mkReg(0);
    Reg#(Bit#(32)) packetReaderCycles <- mkReg(0);
    Reg#(Bit#(32)) payloadFeedCycles  <- mkReg(0);
    Reg#(Bit#(32)) ngramCycles        <- mkReg(0);
    Reg#(Bit#(32)) bitmapCycles       <- mkReg(0);
    Reg#(Bit#(32)) gramCycles         <- mkReg(0);
    Reg#(Bit#(32)) exactCycles        <- mkReg(0);
    Reg#(Bit#(32)) pomCycles          <- mkReg(0);
    Reg#(Bit#(32)) resultWriterCycles <- mkReg(0);

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

    function Bit#(32) countHits(
        Vector#(NBitmapLanes, Bool) hits,
        Vector#(NBitmapLanes, Maybe#(NgramOut)) grams
    );
        Bit#(32) total = 0;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1)
            if (hits[i] && isValid(grams[i])) total = total + 1;
        return total;
    endfunction

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

            if (pktReader.busy) begin
                packetReaderCycles <= packetReaderCycles + 1;
                packetReaderSpan.mark(now);
            end

            if (pktReader.pktReady && metaReady) begin
                payloadFeedCycles <= payloadFeedCycles + 1;
                payloadFeedSpan.mark(now);
            end
            if (!ngram.idle) begin
                ngramCycles <= ngramCycles + 1;
                ngramSpan.mark(now);
            end
            if (!bm0_s1.idle || !bm0_s2.idle || !bm1.idle) begin
                bitmapCycles <= bitmapCycles + 1;
                bitmapSpan.mark(now);
            end
            if (!gram.idle) begin
                gramCycles <= gramCycles + 1;
                gramSpan.mark(now);
            end
            if (exactMatch.inputPending || exactMatch.notEmpty) begin
                exactCycles <= exactCycles + 1;
                exactSpan.mark(now);
            end
            if (portMatch.processing) begin
                pomCycles <= pomCycles + 1;
                pomSpan.mark(now);
            end
        end

        if (state == KDone && !resultWriter.writeDone) begin
            resultWriterCycles <= resultWriterCycles + 1;
            resultWriterSpan.mark(now);
        end
    endrule

    rule latchMeta(state == KProcess && !metaReady && pktReader.metaAvailable);
        let m <- pktReader.nextMeta;
        pktMeta.put(m);
        metaReady <= True;
    endrule

    rule feedPayloadWord(state == KProcess && pktReader.pktReady && metaReady);
        Bit#(512) word = pktReader.getLine;
        Bit#(7)   cnt  = pktReader.lineValidBytes;
        Bool      last = pktReader.lineIsLast;

        if (payTotalLen == 0) begin
            payTotalLen   <= pktReader.bytesRemaining;
            payOff        <= 0;
            payWriteEpoch <= payEpoch;
        end

        ngram.putBytes(word, 0, cnt, last);
        exactMatch.putPayloadWord(word, last, payEpoch);

        pktReader.advanceLine;

        if (last) begin
            payEpoch <= payEpoch + 1;
        end
    endrule

    Reg#(Bool)                                    hasPrev   <- mkReg(False);
    Reg#(Vector#(NBitmapLanes, Maybe#(NgramOut))) prevBatch <- mkRegU;

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

    FIFOF#(Tuple2#(Vector#(NBitmapLanes, Maybe#(NgramOut)),
                   Vector#(NBitmapLanes, Bool)))            gramSideQ <- mkSizedFIFOF(4);

    rule absorbFirst(state == KProcess && ngram.gramsReady && !hasPrev);
        let b <- ngram.getGrams;
        prevBatch <= b;
        hasPrev   <= True;
    endrule

    rule absorbAndDispatch(state == KProcess && ngram.gramsReady && hasPrev);
        let cur <- ngram.getGrams;
        let prev = prevBatch;
        match { .bm0K, .bm1K, .bm1V } = buildKeys(prev, cur, True);
        bm0_s1.lookup(bm0K);
        bm0_s2.lookup(bm0K);
        bm1.lookup(bm1K);
        gramSideQ.enq(tuple2(prev, bm1V));
        gramsExtracted <= gramsExtracted + countValidGrams(prev);
        prevBatch <= cur;
    endrule

    rule flushTail(state == KProcess && hasPrev && ngram.idle && pktReader.pktDone);
        let prev = prevBatch;
        match { .bm0K, .bm1K, .bm1V } = buildKeys(prev, prev, False);
        bm0_s1.lookup(bm0K);
        bm0_s2.lookup(bm0K);
        bm1.lookup(bm1K);
        gramSideQ.enq(tuple2(prev, bm1V));
        gramsExtracted <= gramsExtracted + countValidGrams(prev);
        hasPrev <= False;
    endrule

    FIFOF#(Tuple2#(Vector#(NBitmapLanes, Bool),
                   Vector#(NBitmapLanes, Maybe#(NgramOut))))
        hitPairQ <- mkSizedFIFOF(4);

    rule pairBitmapResults;
        let hits_s1 <- bm0_s1.result;
        let hits_s2 <- bm0_s2.result;
        let hits_b1 <- bm1.result;
        match { .grams, .bm1V } = gramSideQ.first; gramSideQ.deq;

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
        hitPairQ.enq(tuple2(needCuckoo, grams));
    endrule

    Reg#(Bool)                                    scanBusy   <- mkReg(False);
    Reg#(Bit#(7))                                 scanIdx    <- mkReg(0);
    Reg#(Vector#(NBitmapLanes, Bool))             scanNeed   <- mkRegU;
    Reg#(Vector#(NBitmapLanes, Maybe#(NgramOut))) scanGrams  <- mkRegU;

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
        match { .need, .grams } = hitPairQ.first; hitPairQ.deq;
        scanNeed  <= need;
        scanGrams <= grams;
        scanIdx   <= 0;
        scanBusy  <= True;
    endrule

    rule doScan(scanBusy);
        case (nextValidHit(scanIdx, scanNeed, scanGrams)) matches
            tagged Valid .idx: begin
                let g = validValue(scanGrams[idx]);
                Bit#(32) key18 = zeroExtend(makeKey18(g));
                gram.lookupReq(key18, g.anchor, payTotalLen, payWriteEpoch,
                               payOff, True);
                gramLookups <= gramLookups + 1;
                scanIdx <= idx + 1;
            end
            tagged Invalid: begin
                scanBusy <= False;
            end
        endcase
    endrule

    FIFOF#(GramResult) gramRouteQ <- mkSizedFIFOF(4);

    rule collectGramHits(state == KProcess);
        let gr <- gram.lookupResp;
        gramHits <= gramHits + 1;
        gramRouteQ.enq(gr);
    endrule

    rule routeGramResult(state == KProcess && gramRouteQ.notEmpty);
        let gr = gramRouteQ.first; gramRouteQ.deq;
        exactChecks <= exactChecks + 1;
        exactMatch.putRequest(gr.vreq, gr.payLen, gr.epoch, gr.pay_off);
    endrule

    rule drainExact(state == KProcess && exactMatch.notEmpty);
        let r <- exactMatch.getResult;
        if (r.hit) begin
            exactHits <= exactHits + 1;
            if (!pktHitSent) begin
                pktHitSent <= True;
                pomChecks  <= pomChecks + 1;
                pomPending <= tagged Valid PomPktMeta {
                    ruleId:     r.ruleId,
                    ipProto:    pktMeta.getProto,
                    srcPort:    pktMeta.getSrcPort,
                    dstPort:    pktMeta.getDstPort,
                    icmpType:   pktMeta.getIcmpType,
                    icmpCode:   pktMeta.getIcmpCode,
                    isTcp:      pktMeta.isTcp,
                    isUdp:      pktMeta.isUdp,
                    isIcmp:     pktMeta.isIcmp,
                    matchPos:   r.matchPos,
                    payloadLen: r.payLen
                };
            end
        end else begin
            exactMisses <= exactMisses + 1;
        end
    endrule

    rule sendToPom(pomPending matches tagged Valid .m);
        portMatch.putMeta(m);
        pomPending <= tagged Invalid;
    endrule

    rule collectPortResult(state == KProcess &&
                          gram.idle &&
                          !gramRouteQ.notEmpty &&
                          !exactMatch.inputPending && !exactMatch.notEmpty &&
                          portMatch.outputReady);
        let pr <- portMatch.getResult;
        if (pr.hit)
            pomHits <= pomHits + 1;
        else
            pomMisses <= pomMisses + 1;
        resultWriter.addResult(pr.hit, pr.ruleId);
        pktHitSent  <= False;
        payTotalLen <= 0;
        metaReady   <= False;
        pktReader.nextPacket;
    endrule

    Reg#(Bit#(32)) dbgStallCnt <- mkReg(0);
    rule debugStall(state == KProcess && pktReader.pktDone);
        dbgStallCnt <= dbgStallCnt + 1;
        if (dbgStallCnt[16:0] == 0)
            $display("KM stall#%0d ngm=%b s1=%b s2=%b b1=%b gram=%b grQ=%b sideQ=%b hitQ=%b prev=%b ex=%b/%b pmIdle=%b pmOut=%b",
                dbgStallCnt >> 17,
                ngram.idle, bm0_s1.idle, bm0_s2.idle, bm1.idle, gram.idle,
                !gramRouteQ.notEmpty,
                !gramSideQ.notEmpty, !hitPairQ.notEmpty, hasPrev,
                !exactMatch.inputPending, !exactMatch.notEmpty,
                portMatch.idle, portMatch.outputReady);
    endrule

    rule completePktNoMatch(
        state == KProcess &&
        pktReader.pktDone &&
        ngram.idle &&
        bm0_s1.idle &&
        bm0_s2.idle &&
        bm1.idle &&
        gram.idle &&
        !hasPrev &&
        !gramSideQ.notEmpty &&
        !hitPairQ.notEmpty &&
        !scanBusy &&
        !gramRouteQ.notEmpty &&
        !exactMatch.inputPending &&
        !exactMatch.notEmpty &&
        portMatch.idle
    );
        noMatchPkts <= noMatchPkts + 1;
        resultWriter.addResult(False, 0);
        pktHitSent  <= False;
        payTotalLen <= 0;
        metaReady   <= False;
        pktReader.nextPacket;
    endrule

    rule doProcDone(state == KProcess && pktReader.allDone);
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
        payTotalLen        <= 0;
        payOff             <= 0;
        metaReady          <= False;
        pktHitSent         <= False;
        pomPending         <= tagged Invalid;
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
