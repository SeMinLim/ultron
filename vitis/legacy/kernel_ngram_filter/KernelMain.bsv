package KernelMain;

import FIFO::*;
import FIFOF::*;
import Vector::*;

import BitmapUram::*;
import CycleCounter::*;
import ExactPatternTable::*;
import GramMatcher::*;
import NgramExtracter::*;
import PacketParser::*;
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
    BitmapUramIfc         bitmap       <- mkBitmapUram;
    GramMatcherIfc        gram         <- mkGramMatcher;
    NgramExtracterIfc     ngram        <- mkNgramExtracter;
    PacketParserIfc       pktParser    <- mkPacketParser;
    ExactMatchIfc         exactMatch   <- mkExactMatch(patternTable);
    PortOffsetMatcherIfc  portMatch    <- mkPortOffsetMatcher;
    DataLoaderIfc         dataLoader   <- mkDataLoader(bitmap, gram, patternTable, portMatch);
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
    Reg#(Bit#(6))   payOff       <- mkReg(0); // payload byte 0 offset within first BRAM line
    Reg#(Bit#(1))   payEpoch     <- mkReg(0); // flips per packet; selects BRAM half in ExactMatch
    Reg#(Bit#(1))   payWriteEpoch <- mkRegU;  // epoch captured when payload writing begins (frozen)

    // First-hit tracking: only send ONE exactMatch hit per packet to portMatch.
    // Prevents portMatch.outQ accumulation (depth 16) and BSV implicit-condition
    // deadlock from portMatch.putMeta inside a conditional.
    Reg#(Bool)               pktHitSent <- mkReg(False);
    Reg#(Maybe#(PomPktMeta)) pomPending  <- mkReg(tagged Invalid);

    Reg#(Bit#(32)) dataLoaderCycles   <- mkReg(0);
    Reg#(Bit#(32)) packetReaderCycles <- mkReg(0);
    Reg#(Bit#(32)) packetParserCycles <- mkReg(0);
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

    function Bit#(32) countHits(Vector#(NBitmapLanes, Bool) hits);
        Bit#(32) total = 0;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1)
            if (hits[i]) total = total + 1;
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
            packetReaderCycles <= packetReaderCycles + 1;

            if (pktReader.pktReady || pktReader.pktDone)
                packetParserCycles <= packetParserCycles + 1;
            if (!ngram.idle)
                ngramCycles <= ngramCycles + 1;
            if (!bitmap.idle)
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

    // Feed header bytes one at a time until the parser enters payload state.
    // For pure-header packets (no payload) the epoch is bumped here on the last byte.
    rule feedHeaderByte(state == KProcess && pktReader.pktReady && !pktParser.inPayload);
        Bit#(8) b    = pktReader.getByte;
        Bool    last = pktReader.pktLastByte;
        pktParser.putByte(b, last);
        pktReader.advanceByte;
        if (last) payEpoch <= payEpoch + 1;
    endrule

    // Feed one full AXI word per cycle once the parser is in payload state.
    // curLine is the unshifted 512-bit word; payload bytes start at lineByteOffset.
    // On the first word we capture payTotalLen and payOff for use by GramMatcher
    // and ExactMatch.  On the last word we signal the parser and bump the epoch.
    rule feedPayloadWord(state == KProcess && pktReader.pktReady && pktParser.inPayload);
        Bit#(512) word = pktReader.getLine;
        Bit#(6)   off  = pktReader.lineByteOffset;
        Bit#(7)   cnt  = pktReader.lineValidBytes;
        Bool      last = pktReader.lineIsLast;

        // First payload word: record total payload length and the offset of
        // payload byte 0 within this AXI word (pay_off for ExactMatch).
        // Capture once per packet: total payload length, BRAM line offset, and
        // the epoch used for writing (payEpoch before the last-word flip).
        if (payTotalLen == 0) begin
            payTotalLen   <= pktReader.bytesRemaining;
            payOff        <= off;
            payWriteEpoch <= payEpoch;
        end

        // Forward to ngram extractor (word-level, 61 grams/cycle).
        ngram.putBytes(word, zeroExtend(off), cnt, last);

        // Forward raw AXI word to ExactMatch BRAM (64 bytes/cycle, no alignment needed).
        exactMatch.putPayloadWord(word, last, payEpoch);

        pktReader.advanceLine;

        if (last) begin
            pktParser.putByte(0, True);  // reset parser
            payEpoch <= payEpoch + 1;
        end
    endrule

    FIFOF#(Vector#(NBitmapLanes, Maybe#(NgramOut))) gramSideQ <- mkSizedFIFOF(4);

    rule dispatchGrams(state == KProcess && ngram.gramsReady);
        let grams <- ngram.getGrams;
        gramsExtracted <= gramsExtracted + countValidGrams(grams);
        Vector#(NBitmapLanes, Bit#(21)) keys = newVector;
        for (Integer i = 0; i < valueOf(NBitmapLanes); i = i + 1) begin
            case (grams[i]) matches
                tagged Valid .g: keys[i] = {g.gram[22:16], g.gram[14:8], g.gram[6:0]};
                tagged Invalid:  keys[i] = 0;
            endcase
        end
        bitmap.lookup(keys);
        gramSideQ.enq(grams);
    endrule

    FIFOF#(Tuple2#(Vector#(NBitmapLanes, Bool),
                   Vector#(NBitmapLanes, Maybe#(NgramOut)))) hitPairQ <- mkSizedFIFOF(4);

    rule pairBitmapHits;
        let hits  <- bitmap.result;
        let grams = gramSideQ.first; gramSideQ.deq;
        bitmapPassed <= bitmapPassed + countHits(hits);
        hitPairQ.enq(tuple2(hits, grams));
    endrule

    Reg#(Bool)                                    scanBusy  <- mkReg(False);
    Reg#(Bit#(7))                                 scanIdx   <- mkReg(0);
    Reg#(Vector#(NBitmapLanes, Bool))             scanHits  <- mkRegU;
    Reg#(Vector#(NBitmapLanes, Maybe#(NgramOut))) scanGrams <- mkRegU;

    rule startScan(!scanBusy && hitPairQ.notEmpty);
        let {hits, grams} = hitPairQ.first; hitPairQ.deq;
        scanHits  <= hits;
        scanGrams <= grams;
        scanIdx   <= 0;
        scanBusy  <= True;
    endrule

    rule doScan(scanBusy);
        Bool hit = scanHits[scanIdx];
        case (scanGrams[scanIdx]) matches
            tagged Valid .g: if (hit) begin
                gram.lookupReq(g.gram, g.anchor, payTotalLen, payWriteEpoch, payOff);
                gramLookups <= gramLookups + 1;
            end
            tagged Invalid:  noAction;
        endcase
        if (scanIdx == fromInteger(valueOf(NBitmapLanes) - 1))
            scanBusy <= False;
        else
            scanIdx <= scanIdx + 1;
    endrule


    // GramMatcher filters sentinels internally — outQ only contains valid hits.
    // No gramStageQ or sentinel-drain rules needed.
    rule collectGramHits(state == KProcess);
        let gr <- gram.lookupResp;
        let vr = validValue(gr.vreq);
        gramHits    <= gramHits + 1;
        exactChecks <= exactChecks + 1;
        $display("KM gramHit rule=%0d anchor=%0d pre=%0d post=%0d len=%0d payLen=%0d",
                 vr.ruleId, vr.anchor, vr.pre, vr.post, vr.len, gr.payLen);
        exactMatch.putRequest(vr, gr.payLen, gr.epoch, gr.pay_off);
    endrule

    // Drain exactMatch results into registers only — no method calls that could
    // block.  Only the FIRST hit per packet is staged into pomPending; subsequent
    // hits are counted but discarded so portMatch.pendingQ (depth 16) never fills.
    rule drainExact(state == KProcess && exactMatch.notEmpty);
        let r <- exactMatch.getResult;
        $display("KM exactResult hit=%b ruleId=%0d matchPos=%0d", r.hit, r.ruleId, r.matchPos);
        if (r.hit) begin
            exactHits <= exactHits + 1;
            if (!pktHitSent) begin
                pktHitSent <= True;
                pomChecks  <= pomChecks + 1;
                pomPending <= tagged Valid PomPktMeta {
                    ruleId:     r.ruleId,
                    ipProto:    pktParser.getProto,
                    srcPort:    pktParser.getSrcPort,
                    dstPort:    pktParser.getDstPort,
                    icmpType:   pktParser.getIcmpType,
                    icmpCode:   pktParser.getIcmpCode,
                    isTcp:      pktParser.isTcp,
                    isUdp:      pktParser.isUdp,
                    isIcmp:     pktParser.isIcmp,
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
                          !exactMatch.inputPending && !exactMatch.notEmpty &&
                          portMatch.outputReady);
        let pr <- portMatch.getResult;
        $display("KM portResult hit=%b ruleId=%0d", pr.hit, pr.ruleId);
        if (pr.hit)
            pomHits <= pomHits + 1;
        else
            pomMisses <= pomMisses + 1;
        resultWriter.addResult(pr.hit, pr.ruleId);
        pktHitSent  <= False;
        payTotalLen <= 0;
        pktReader.nextPacket;
    endrule

    rule completePktNoMatch(
        state == KProcess &&
        pktReader.pktDone &&
        ngram.idle &&
        bitmap.idle &&
        gram.idle &&
        !gramSideQ.notEmpty &&
        !hitPairQ.notEmpty &&
        !scanBusy &&
        !exactMatch.inputPending &&
        !exactMatch.notEmpty &&
        portMatch.idle
    );
        noMatchPkts <= noMatchPkts + 1;
        resultWriter.addResult(False, 0);
        pktHitSent  <= False;
        payTotalLen <= 0;
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
            packetParserCycles: packetParserCycles,
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
            noMatchPkts:        noMatchPkts
        };
        resultSummary <= summary;
        state <= KWrite;
    endrule

    rule doWrite(state == KWrite);
        $display("KM write start");
        resultWriter.startWrite(rResultBase, rPktCount, resultSummary);
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
        packetParserCycles <= 0;
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
        resultSummary      <= unpack(0);
        payTotalLen        <= 0;
        payOff             <= 0;
        pktHitSent         <= False;
        pomPending         <= tagged Invalid;
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
