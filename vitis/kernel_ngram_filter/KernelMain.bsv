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

typedef enum { KIdle, KInit, KProcess, KWrite, KDone } KState deriving (Bits, Eq, FShow);

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

    // --- Cycle counters: one per pipeline section ---
    CycleCounterIfc timerDb    <- mkCycleCounter;  // DB load phase
    CycleCounterIfc timerPkt   <- mkCycleCounter;  // Packet processing phase
    CycleCounterIfc timerTotal <- mkCycleCounter;  // End-to-end

    Vector#(3, FIFO#(MemReq))     rdReqQs  <- replicateM(mkFIFO);
    Vector#(3, FIFO#(MemReq))     wrReqQs  <- replicateM(mkFIFO);
    Vector#(3, FIFO#(Bit#(512)))  wrWordQs <- replicateM(mkFIFO);
    Vector#(3, FIFOF#(Bit#(512))) rdWordQs <- replicateM(mkSizedFIFOF(16));

    FIFO#(Bool) doneQ <- mkFIFO;
    Reg#(KState) state <- mkReg(KIdle);

    Reg#(Bit#(32)) rPktCount   <- mkRegU;
    Reg#(Bit#(64)) rPktBase    <- mkRegU;
    Reg#(Bit#(64)) rResultBase <- mkRegU;

    Reg#(Bit#(512)) payBuf  <- mkReg(0);
    Reg#(Bit#(7))   payBufN <- mkReg(0);
    Reg#(Bit#(32))  payLen  <- mkReg(0);

    Reg#(Bit#(32)) dataLoaderCycles   <- mkReg(0);
    Reg#(Bit#(32)) packetReaderCycles <- mkReg(0);
    Reg#(Bit#(32)) packetParserCycles <- mkReg(0);
    Reg#(Bit#(32)) ngramCycles        <- mkReg(0);
    Reg#(Bit#(32)) bitmapCycles       <- mkReg(0);
    Reg#(Bit#(32)) gramCycles         <- mkReg(0);
    Reg#(Bit#(32)) exactCycles        <- mkReg(0);
    Reg#(Bit#(32)) portCycles         <- mkReg(0);
    Reg#(Bit#(32)) resultWriterCycles <- mkReg(0);
    Reg#(Bit#(32)) gramsExtracted     <- mkReg(0);
    Reg#(Bit#(32)) bitmapPassed       <- mkReg(0);
    Reg#(Bit#(32)) gramLookups        <- mkReg(0);
    Reg#(Bit#(32)) gramHits           <- mkReg(0);
    Reg#(Bit#(32)) exactChecks        <- mkReg(0);
    Reg#(Bit#(32)) exactHits          <- mkReg(0);
    Reg#(Bit#(32)) exactMisses        <- mkReg(0);
    Reg#(Bit#(32)) portChecks         <- mkReg(0);
    Reg#(Bit#(32)) portHits           <- mkReg(0);
    Reg#(Bit#(32)) portMisses         <- mkReg(0);
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
            if (!portMatch.idle)
                portCycles <= portCycles + 1;
        end

        if (state == KDone && !resultWriter.writeDone)
            resultWriterCycles <= resultWriterCycles + 1;
    endrule

    rule feedByte(state == KProcess && pktReader.pktReady);
        Bit#(8) b    = pktReader.getByte;
        Bool    last = pktReader.pktLastByte;
        pktParser.putByte(b, last);
        pktReader.advanceByte;

        if (pktParser.inPayload) begin
            Bit#(512) nextPayBuf = (payBuf >> 8) | (zeroExtend(b) << 504);
            Bit#(7)   nextN      = payBufN + 1;
            Bit#(32)  nextLen    = payLen + 1;

            if (payBufN == 63 || last) begin
                Bit#(7) cnt = last ? truncate(payBufN) + 1 : 64;
                exactMatch.putPayloadWord(nextPayBuf, last);
                ngram.putBytes(nextPayBuf, 0, truncate(cnt), last);
                payBufN <= 0;
                payBuf  <= 0;
                payLen  <= nextLen;
            end else begin
                payBuf  <= nextPayBuf;
                payBufN <= nextN;
                payLen  <= nextLen;
            end
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
                gram.lookupReq(g.gram, g.anchor);
                gramLookups <= gramLookups + 1;
            end
            tagged Invalid:  noAction;
        endcase
        if (scanIdx == fromInteger(valueOf(NBitmapLanes) - 1))
            scanBusy <= False;
        else
            scanIdx <= scanIdx + 1;
    endrule

    rule collectGramHits(state == KProcess);
        let r <- gram.lookupResp;
        case (r) matches
            tagged Valid .vr: begin
                gramHits <= gramHits + 1;
                exactChecks <= exactChecks + 1;
                $display("KM gramHit rule=%0d anchor=%0d pre=%0d post=%0d len=%0d payLen=%0d",
                         vr.ruleId, vr.anchor, vr.pre, vr.post, vr.len, payLen);
                exactMatch.putRequest(vr, payLen);
            end
            tagged Invalid: noAction;
        endcase
    endrule

    rule drainExact(state == KProcess && !exactMatch.inputPending && exactMatch.notEmpty);
        let r <- exactMatch.getResult;
        $display("KM exactResult hit=%b ruleId=%0d matchPos=%0d", r.hit, r.ruleId, r.matchPos);
        if (r.hit) begin
            exactHits <= exactHits + 1;
            portChecks <= portChecks + 1;
            portMatch.putMeta(PomPktMeta {
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
                payloadLen: payLen
            });
        end else begin
            exactMisses <= exactMisses + 1;
            resultWriter.addResult(False, 0);
            payBuf  <= 0;
            payBufN <= 0;
            payLen  <= 0;
            pktReader.nextPacket;
        end
    endrule

    rule collectPortResult(state == KProcess && portMatch.outputReady);
        let pr <- portMatch.getResult;
        $display("KM portResult hit=%b ruleId=%0d", pr.hit, pr.ruleId);
        if (pr.hit)
            portHits <= portHits + 1;
        else
            portMisses <= portMisses + 1;
        resultWriter.addResult(pr.hit, pr.ruleId);
        payBuf  <= 0;
        payBufN <= 0;
        payLen  <= 0;
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
        payBuf  <= 0;
        payBufN <= 0;
        payLen  <= 0;
        pktReader.nextPacket;
    endrule

    rule doProcDone(state == KProcess && pktReader.allDone);
        $display("KM process done");
        timerPkt.markDone;
        timerTotal.markDone;
        state <= KWrite;
    endrule

    rule doInit(state == KInit && dataLoader.loadDone);
        $display("KM init done");
        timerDb.markDone;
        timerPkt.markStart;
        pktReader.startRead(rPktBase, rPktCount);
        state <= KProcess;
    endrule

    rule doWrite(state == KWrite);
        $display("KM write start");
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
            portCycles:         portCycles,
            resultWriterCycles: resultWriterCycles,
            gramsExtracted:     gramsExtracted,
            bitmapPassed:       bitmapPassed,
            gramLookups:        gramLookups,
            gramHits:           gramHits,
            exactChecks:        exactChecks,
            exactHits:          exactHits,
            exactMisses:        exactMisses,
            portChecks:         portChecks,
            portHits:           portHits,
            portMisses:         portMisses,
            noMatchPkts:        noMatchPkts
        };
        resultSummary <= summary;
        resultWriter.startWrite(rResultBase, rPktCount, summary);
        state <= KDone;
    endrule

    rule doDone(state == KDone && resultWriter.writeDone);
        $display("KM done");
        doneQ.enq(True);
        state <= KIdle;
    endrule

    // --- AXI port interfaces ---
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
        portCycles         <= 0;
        resultWriterCycles <= 0;
        gramsExtracted     <= 0;
        bitmapPassed       <= 0;
        gramLookups        <= 0;
        gramHits           <= 0;
        exactChecks        <= 0;
        exactHits          <= 0;
        exactMisses        <= 0;
        portChecks         <= 0;
        portHits           <= 0;
        portMisses         <= 0;
        noMatchPkts        <= 0;
        resultSummary      <= unpack(0);
        payBuf             <= 0;
        payBufN            <= 0;
        payLen             <= 0;
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
