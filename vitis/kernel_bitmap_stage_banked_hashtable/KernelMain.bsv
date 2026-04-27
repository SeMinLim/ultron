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
    BitmapUramIfc         bitmap0      <- mkBitmapUram;
    BitmapUramIfc         bitmap1      <- mkBitmapUram;  // stage-2: next-gram bitmap
    GramMatcherIfc        gram         <- mkGramMatcher;
    NgramExtracterIfc     ngram        <- mkNgramExtracter;
    PacketMetaIfc         pktMeta      <- mkPacketMeta;
    ExactMatchIfc         exactMatch   <- mkExactMatch(patternTable);
    PortOffsetMatcherIfc  portMatch    <- mkPortOffsetMatcher;
    DataLoaderIfc         dataLoader   <- mkDataLoader(bitmap0, bitmap1, gram, patternTable, portMatch);
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

    Reg#(Bit#(32))  payTotalLen  <- mkReg(0); // total payload length; 0 = not yet captured
    Reg#(Bit#(6))   payOff       <- mkReg(0); // always 0 now; host 64B-aligns payload
    Reg#(Bit#(1))   payEpoch     <- mkReg(0); // flips per packet; selects BRAM half in ExactMatch
    Reg#(Bit#(1))   payWriteEpoch <- mkRegU;  // epoch captured when payload writing begins (frozen)
    Reg#(Bool)      metaReady    <- mkReg(False); // current packet's meta loaded into pktMeta

    // First-hit tracking: only send ONE exactMatch hit per packet to portMatch.
    // Prevents portMatch.outQ accumulation (depth 16) and BSV implicit-condition
    // deadlock from portMatch.putMeta inside a conditional.
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
        if (state == KInit && !dataLoader.loadDone)
            dataLoaderCycles <= dataLoaderCycles + 1;

        if (state == KProcess && !pktReader.allDone) begin
            // pktReader.busy excludes the PRFeedPkt-with-bytesLeft=0 drain
            // window, so this number reflects time the reader is actually
            // making progress rather than waiting on the back-end pipeline.
            if (pktReader.busy)
                packetReaderCycles <= packetReaderCycles + 1;
            // Cycle in which feedPayloadWord could fire (= a payload word is
            // being injected into ngram).  Excludes pktDone wait window.
            if (pktReader.pktReady && metaReady)
                payloadFeedCycles <= payloadFeedCycles + 1;
            if (!ngram.idle)
                ngramCycles <= ngramCycles + 1;
            if (!bitmap0.idle || !bitmap1.idle)
                bitmapCycles <= bitmapCycles + 1;
            if (!gram.idle)
                gramCycles <= gramCycles + 1;
            if (exactMatch.inputPending || exactMatch.notEmpty)
                exactCycles <= exactCycles + 1;
            if (portMatch.processing)
                pomCycles <= pomCycles + 1;
        end

        if (state == KDone && !resultWriter.writeDone)
            resultWriterCycles <= resultWriterCycles + 1;
    endrule

    // Load the current packet's metadata (ip proto, ports, icmp fields) into
    // pktMeta once per packet before payload streaming begins. The reader
    // enqueues a meta entry whenever it kicks off a packet's payload read.
    rule latchMeta(state == KProcess && !metaReady && pktReader.metaAvailable);
        let m <- pktReader.nextMeta;
        pktMeta.put(m);
        metaReady <= True;
    endrule

    // Feed one full AXI word per cycle. Host pre-parses and 64B-aligns the
    // payload, so there is no header walk anymore and payOff is always 0.
    // Capture payTotalLen and the write epoch on the first word, bump the
    // epoch on the last word.
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

    // -------------------------------------------------------------------
    // bitmap0 + bitmap1 are looked up in parallel for every batch (c_ref's
    // new order: bm0 → bm1 → cuckoo).  bitmap1 is keyed on the gram at
    // anchor+3 of every lane.  Within one 64-lane batch lanes 0..60 can
    // source their bm1 key from the same batch (lane i+3); lanes 61..63
    // need lanes 0..2 of the NEXT batch.  We therefore buffer one batch
    // before dispatching ("prevBatch") and rely on a small flush rule to
    // emit the held last batch when ngram has gone idle.
    Reg#(Bool)                                    hasPrev   <- mkReg(False);
    Reg#(Vector#(NBitmapLanes, Maybe#(NgramOut))) prevBatch <- mkRegU;

    // 18-bit gram key matches ref/ultron/c_ref/mky_backup/bitmap.h:
    //   {byte0[5:0], byte1[5:0], byte2[5:0]}
    // The NgramExtracter packs each fold-cased byte into 8-bit slots of
    // g.gram (b0 at [23:16], b1 at [15:8], b2 at [7:0]) so we slice the
    // low 6 bits of each.
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
            // Source for lane i's bm1 key: gram at anchor+3.
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

    // Side-channel carrying both grams and the bm1-validity vector to
    // pairBitmapResults.  The latter computes viable_stage = (bm0_hit &&
    // bm1_valid && bm1_hit) ? 2 : (bm0_hit ? 1 : 0) per lane.
    FIFOF#(Tuple2#(Vector#(NBitmapLanes, Maybe#(NgramOut)),
                   Vector#(NBitmapLanes, Bool)))            gramSideQ <- mkSizedFIFOF(4);

    // First batch arrives → just buffer; nothing to dispatch yet because we
    // need a lookahead for the tail bm1 keys.
    rule absorbFirst(state == KProcess && ngram.gramsReady && !hasPrev);
        let b <- ngram.getGrams;
        prevBatch <= b;
        hasPrev   <= True;
    endrule

    // Subsequent batch arrives → dispatch the held prev batch with bm1 keys
    // sourced from this new (lookahead) batch's first 3 lanes.
    rule absorbAndDispatch(state == KProcess && ngram.gramsReady && hasPrev);
        let cur <- ngram.getGrams;
        let prev = prevBatch;
        match { .bm0K, .bm1K, .bm1V } = buildKeys(prev, cur, True);
        bitmap0.lookup(bm0K);
        bitmap1.lookup(bm1K);
        gramSideQ.enq(tuple2(prev, bm1V));
        gramsExtracted <= gramsExtracted + countValidGrams(prev);
        prevBatch <= cur;
    endrule

    // No more batches will come for this packet — flush the held batch with
    // bm1V=False on the trailing 3 lanes.  Fires at packet boundary; once.
    rule flushTail(state == KProcess && hasPrev && ngram.idle && pktReader.pktDone);
        let prev = prevBatch;
        match { .bm0K, .bm1K, .bm1V } = buildKeys(prev, prev, False);
        bitmap0.lookup(bm0K);
        bitmap1.lookup(bm1K);
        gramSideQ.enq(tuple2(prev, bm1V));
        gramsExtracted <= gramsExtracted + countValidGrams(prev);
        hasPrev <= False;
    endrule

    // Pair bm0 and bm1 results.  Per-lane viability:
    //   viable2 = bm0_hit && bm1_valid && bm1_hit
    // Lanes that miss bm0 are dropped at scan time (nextValidHit only walks
    // over (bm0_hit && gram_valid) lanes).
    FIFOF#(Tuple3#(Vector#(NBitmapLanes, Bool),                // bm0 hits
                   Vector#(NBitmapLanes, Bool),                // viable2
                   Vector#(NBitmapLanes, Maybe#(NgramOut))))   // grams
        hitPairQ <- mkSizedFIFOF(4);

    rule pairBitmapResults;
        let hits0 <- bitmap0.result;
        let hits1 <- bitmap1.result;
        match { .grams, .bm1V } = gramSideQ.first; gramSideQ.deq;
        bitmapPassed  <= bitmapPassed  + countHits(hits0, grams);
        // Per-lane viable2 vector.
        Vector#(NBitmapLanes, Bool) viable = newVector;
        Bit#(32) viableCnt = 0;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            Bool v = hits0[i] && bm1V[i] && hits1[i] && isValid(grams[i]);
            viable[i] = v;
            if (v) viableCnt = viableCnt + 1;
        end
        // bitmap_stage1 stats are now "anchors that survived bm0 AND bm1".
        // They are no longer "rule-specific stage-2 verifications" because
        // bitmap1 fires before the cuckoo identifies the rule.
        stage2Checked <= stage2Checked + countHits(hits0, grams);
        stage2Passed  <= stage2Passed  + viableCnt;
        hitPairQ.enq(tuple3(hits0, viable, grams));
    endrule

    Reg#(Bool)                                    scanBusy   <- mkReg(False);
    Reg#(Bit#(7))                                 scanIdx    <- mkReg(0);
    Reg#(Vector#(NBitmapLanes, Bool))             scanHits   <- mkRegU;
    Reg#(Vector#(NBitmapLanes, Bool))             scanViable <- mkRegU;
    Reg#(Vector#(NBitmapLanes, Maybe#(NgramOut))) scanGrams  <- mkRegU;

    // Find the lowest lane index >= start that is both a bitmap hit and has a
    // valid gram.  Returns Invalid when no such lane exists in [start, NBitmapLanes).
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
        match { .hits, .viable, .grams } = hitPairQ.first; hitPairQ.deq;
        scanHits   <= hits;
        scanViable <= viable;
        scanGrams  <= grams;
        scanIdx    <= 0;
        scanBusy   <= True;
    endrule

    // One gram lookup issued per cycle, jumping directly to the next hit lane.
    // Batches with no hits complete in a single cycle instead of burning 64 cycles.
    rule doScan(scanBusy);
        case (nextValidHit(scanIdx, scanHits, scanGrams)) matches
            tagged Valid .idx: begin
                let g = validValue(scanGrams[idx]);
                Bit#(32) key18 = zeroExtend(makeKey18(g));
                gram.lookupReq(key18, g.anchor, payTotalLen, payWriteEpoch,
                               payOff, scanViable[idx]);
                gramLookups <= gramLookups + 1;
                scanIdx <= idx + 1;
            end
            tagged Invalid: begin
                scanBusy <= False;
            end
        endcase
    endrule


    // GramMatcher filters sentinels internally — outQ only contains valid hits.
    // Routing now matches c_ref's match_scan: a stage-2 rule is only accepted
    // if the pre-cuckoo bitmap1 lookup at anchor+3 passed (info.viable2).
    // Stage-1 rules always pass.
    FIFOF#(GramResult) gramRouteQ <- mkSizedFIFOF(4);

    rule collectGramHits(state == KProcess);
        let gr <- gram.lookupResp;
        gramHits <= gramHits + 1;
        gramRouteQ.enq(gr);
    endrule

    rule routeGramResult(state == KProcess && gramRouteQ.notEmpty);
        let gr = gramRouteQ.first; gramRouteQ.deq;
        Bool needsStage2 = gr.vreq.stage2;
        Bool ok = !needsStage2 || gr.viable2;
        if (ok) begin
            exactChecks <= exactChecks + 1;
            exactMatch.putRequest(gr.vreq, gr.payLen, gr.epoch, gr.pay_off);
        end
        // Drop stage-2 rules whose anchor+3 missed bitmap1.
    endrule

    // Drain exactMatch results into registers only — no method calls that could
    // block.  Only the FIRST hit per packet is staged into pomPending; subsequent
    // hits are counted but discarded so portMatch.pendingQ (depth 16) never fills.
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

    // Forward the staged portMatch request.  Separate rule so drainExact never
    // sees portMatch.pendingQ.notFull as a CAN_FIRE condition.
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

    // Diagnostic: fires every cycle that pktDone is True but the packet can't
    // complete, showing which conditions are blocking.
    Reg#(Bit#(32)) dbgStallCnt <- mkReg(0);
    rule debugStall(state == KProcess && pktReader.pktDone);
        dbgStallCnt <= dbgStallCnt + 1;
        if (dbgStallCnt[16:0] == 0)  // print every 131072 cycles
            $display("KM stall#%0d ngm=%b bm0=%b bm1=%b gram=%b grQ=%b sideQ=%b hitQ=%b prev=%b ex=%b/%b pmIdle=%b pmOut=%b",
                dbgStallCnt >> 17,
                ngram.idle, bitmap0.idle, bitmap1.idle, gram.idle,
                !gramRouteQ.notEmpty,
                !gramSideQ.notEmpty, !hitPairQ.notEmpty, hasPrev,
                !exactMatch.inputPending, !exactMatch.notEmpty,
                portMatch.idle, portMatch.outputReady);
    endrule

    rule completePktNoMatch(
        state == KProcess &&
        pktReader.pktDone &&
        ngram.idle &&
        bitmap0.idle &&
        bitmap1.idle &&
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
            stage2Passed:       stage2Passed
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
