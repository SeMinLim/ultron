package ResultWriter;

// Result buffer layout:
//   [0..192)              192B summary: 48 x u32 counters (3 x 64B lines)

import FIFOF::*;
import Vector::*;

typedef struct {
    Bit#(32) dbCycles;
    Bit#(32) pktCycles;
    Bit#(32) totalCycles;
    Bit#(32) dataLoaderCycles;
    Bit#(32) packetReaderCycles;
    Bit#(32) payloadFeedCycles;
    Bit#(32) ngramCycles;
    Bit#(32) bitmapCycles;
    Bit#(32) gramCycles;
    Bit#(32) exactCycles;
    Bit#(32) pomCycles;
    Bit#(32) resultWriterCycles;
    Bit#(32) gramsExtracted;
    Bit#(32) bitmapPassed;
    Bit#(32) gramLookups;
    Bit#(32) gramHits;
    Bit#(32) exactChecks;
    Bit#(32) exactHits;
    Bit#(32) exactMisses;
    Bit#(32) pomChecks;
    Bit#(32) pomHits;
    Bit#(32) pomMisses;
    Bit#(32) noMatchPkts;
    Bit#(32) stage2Checked;
    Bit#(32) stage2Passed;
    Bit#(32) gapBackend;
    Bit#(32) gapHbm;
    Bit#(32) gapReaderOther;
    Bit#(32) gapMetaWait;
    Bit#(32) gapNextStart;
    Bit#(32) readerDescCycles;
    Bit#(32) readerStartCycles;
    Bit#(32) readerFirstLineWaitCycles;
    Bit#(32) readerRespCycles;
    Bit#(32) epochFullCycles;
    Bit#(32) resultAcceptBlockCycles;
    Bit#(32) exactInputBlockCycles;
    Bit#(32) dataLoaderE2E;
    Bit#(32) packetReaderE2E;
    Bit#(32) payloadFeedE2E;
    Bit#(32) ngramE2E;
    Bit#(32) bitmapE2E;
    Bit#(32) gramE2E;
    Bit#(32) exactE2E;
    Bit#(32) pomE2E;
    Bit#(32) resultWriterE2E;
    Bit#(32) bloomCycles;
    Bit#(32) bloomE2E;
    Bit#(32) bloomRejects;
} ResultSummary deriving (Bits, Eq, FShow);

interface ResultWriterIfc;
    method Action configure(Bit#(64) resultBase, Bit#(32) pktCount);
    method Bool canAccept(Bit#(32) pktIdx);
    method Action addResult(Bit#(32) pktIdx, Bool matched, Bit#(16) ruleId);
    method Action startWrite(ResultSummary summary);
    method Bool   writeDone;
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) writeReq;
    method ActionValue#(Bit#(512)) writeWord;
endinterface

// Reorder buffer depth — must be > NEpoch (8) to guarantee no slot collision.
typedef 16 ResultOrderDepth;

typedef struct {
    Bool     valid;
    Bit#(32) pktIdx;
    Bool     matched;
    Bit#(16) ruleId;
} OrderedResult deriving (Bits, Eq, FShow);

module mkResultWriter(ResultWriterIfc);

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) writeReqQ  <- mkFIFOF;
    FIFOF#(Bit#(512))                   writeWordQ <- mkSizedFIFOF(8);

    Reg#(Bit#(32)) matchedCount   <- mkReg(0);
    Reg#(Bit#(32)) processedCount <- mkReg(0);

    Reg#(Bool)     done           <- mkReg(False);
    Reg#(Bit#(64)) resultBase_r   <- mkReg(0);
    Reg#(Bit#(32)) pktTotal       <- mkReg(0);

    Reg#(Bit#(4))       sumPhase <- mkReg(0);
    Reg#(ResultSummary) summaryR <- mkReg(unpack(0));

    // Hold off done until the AXI summary write drains to DDR; otherwise the
    // host can sync before bvalid and read back zeros.
    Reg#(Bit#(8)) drainTicks <- mkReg(0);

    // Reorder buffer: absorbs out-of-order retire results, drains in pktIdx order.
    Vector#(ResultOrderDepth, Reg#(OrderedResult)) reorderBuf <-
        replicateM(mkReg(OrderedResult { valid: False, pktIdx: 0,
                                         matched: False, ruleId: 0 }));
    Reg#(Bit#(32)) nextOutPktIdx <- mkReg(0);

    // Per-packet result accumulator: packs 16 x u32 into one 512-bit line.
    // Encoding: bit0=matched, bits[16:1]=ruleId, bits[31:17]=reserved.
    Reg#(Bit#(512)) perPktAccum  <- mkReg(0);
    Reg#(Bit#(4))   perPktSubIdx <- mkReg(0);
    // Completed 512-bit lines waiting to be written; 512 entries = 8192 packets max.
    FIFOF#(Bit#(512)) perPktLineQ <- mkSizedFIFOF(512);

    // Drain one slot per cycle in nextOutPktIdx order, bump counters, accumulate result.
    // ResultOrderDepth=16=2^4, so low 4 bits of pktIdx are the slot index.
    rule drainOrdered(sumPhase == 0 && !done);
        Bit#(4) slot = truncate(nextOutPktIdx);
        let e = reorderBuf[slot];
        if (e.valid && e.pktIdx == nextOutPktIdx) begin
            processedCount <= processedCount + 1;
            if (e.matched) matchedCount <= matchedCount + 1;
            reorderBuf[slot] <= OrderedResult { valid: False, pktIdx: 0,
                                                matched: False, ruleId: 0 };
            nextOutPktIdx <= nextOutPktIdx + 1;

            // Pack result u32 into accumulator at bit position subIdx*32.
            Bit#(32)  rword    = {15'b0, e.ruleId, pack(e.matched)};
            Bit#(9)   shift    = {zeroExtend(perPktSubIdx), 5'b0};
            Bit#(512) newAccum = perPktAccum | (zeroExtend(rword) << shift);
            Bool isLast = (nextOutPktIdx + 1 == pktTotal);
            Bool lineFull = (perPktSubIdx == 4'hF);
            if (lineFull || isLast) begin
                perPktLineQ.enq(newAccum);
                perPktAccum  <= 0;
                perPktSubIdx <= 0;
            end else begin
                perPktAccum  <= newAccum;
                perPktSubIdx <= perPktSubIdx + 1;
            end
        end
    endrule

    function Bit#(512) packSummary0(ResultSummary s,
                                    Bit#(32) matched, Bit#(32) processed);
        Bit#(512) w = 0;
        w[31:0]    = matched;
        w[63:32]   = processed;
        w[95:64]   = s.dbCycles;
        w[127:96]  = s.pktCycles;
        w[159:128] = s.totalCycles;
        w[191:160] = s.dataLoaderCycles;
        w[223:192] = s.packetReaderCycles;
        w[255:224] = s.payloadFeedCycles;
        w[287:256] = s.ngramCycles;
        w[319:288] = s.bitmapCycles;
        w[351:320] = s.gramCycles;
        w[383:352] = s.exactCycles;
        w[415:384] = s.pomCycles;
        w[447:416] = s.resultWriterCycles;
        w[479:448] = s.gramsExtracted;
        w[511:480] = s.bitmapPassed;
        return w;
    endfunction

    function Bit#(512) packSummary1(ResultSummary s);
        Bit#(512) w = 0;
        w[31:0]    = s.gramLookups;
        w[63:32]   = s.gramHits;
        w[95:64]   = s.exactChecks;
        w[127:96]  = s.exactHits;
        w[159:128] = s.exactMisses;
        w[191:160] = s.pomChecks;
        w[223:192] = s.pomHits;
        w[255:224] = s.pomMisses;
        w[287:256] = s.noMatchPkts;
        w[319:288] = s.stage2Checked;
        w[351:320] = s.stage2Passed;
        w[383:352] = s.gapBackend;
        w[415:384] = s.gapHbm;
        w[447:416] = s.gapReaderOther;
        w[479:448] = s.gapMetaWait;
        w[511:480] = s.gapNextStart;
        return w;
    endfunction

    function Bit#(512) packSummary2(ResultSummary s);
        Bit#(512) w = 0;
        w[31:0]    = s.dataLoaderE2E;
        w[63:32]   = s.packetReaderE2E;
        w[95:64]   = s.payloadFeedE2E;
        w[127:96]  = s.ngramE2E;
        w[159:128] = s.bitmapE2E;
        w[191:160] = s.gramE2E;
        w[223:192] = s.exactE2E;
        w[255:224] = s.pomE2E;
        w[287:256] = s.resultWriterE2E;
        w[319:288] = s.readerDescCycles;
        w[351:320] = s.readerStartCycles;
        w[383:352] = s.readerFirstLineWaitCycles;
        w[415:384] = s.readerRespCycles;
        w[447:416] = s.epochFullCycles;
        w[479:448] = s.resultAcceptBlockCycles;
        w[511:480] = s.exactInputBlockCycles;
        return w;
    endfunction

    // word3: bloom stage stats at currently-unread offsets (>= 220).
    function Bit#(512) packSummary3(ResultSummary s);
        Bit#(512) w = 0;
        w[255:224] = s.bloomCycles;    // blob offset 220
        w[287:256] = s.bloomE2E;       // blob offset 224
        w[319:288] = s.bloomRejects;   // blob offset 228
        return w;
    endfunction

    // Phase 1: emit one write request covering all per-packet result u32s.
    // Layout: resultBase+256 .. +align_up(pktTotal*4, 64).
    rule emitPerPktReq(sumPhase == 1);
        Bit#(64) perPktBytes = zeroExtend(((pktTotal << 2) + 63) & ~63);
        writeReqQ.enq(tuple2(resultBase_r + 256, perPktBytes));
        sumPhase <= 2;
    endrule

    // Phase 2: stream per-packet lines into writeWordQ; advance when FIFO empty.
    rule emitPerPktWords(sumPhase == 2);
        if (perPktLineQ.notEmpty) begin
            writeWordQ.enq(perPktLineQ.first);
            perPktLineQ.deq;
        end else begin
            sumPhase <= 3;
        end
    endrule

    // Phases 3-6: summary (unchanged content, phases shifted up by 2).
    rule emitSummary0(sumPhase == 3);
        writeReqQ.enq(tuple2(resultBase_r, 256));
        writeWordQ.enq(packSummary0(summaryR, matchedCount, processedCount));
        sumPhase <= 4;
    endrule

    rule emitSummary1(sumPhase == 4);
        writeWordQ.enq(packSummary1(summaryR));
        sumPhase <= 5;
    endrule

    rule emitSummary2(sumPhase == 5);
        writeWordQ.enq(packSummary2(summaryR));
        sumPhase <= 6;
    endrule

    rule emitSummary3(sumPhase == 6);
        writeWordQ.enq(packSummary3(summaryR));
        sumPhase   <= 0;
        drainTicks <= 128;
    endrule

    rule countDrain(drainTicks > 0 && !done);
        drainTicks <= drainTicks - 1;
        if (drainTicks == 1) done <= True;
    endrule

    method Action configure(Bit#(64) resultBase, Bit#(32) pktCount);
        resultBase_r   <= resultBase;
        pktTotal       <= pktCount;
        matchedCount   <= 0;
        processedCount <= 0;
        nextOutPktIdx  <= 0;
        perPktAccum    <= 0;
        perPktSubIdx   <= 0;
        done           <= False;
        sumPhase       <= 0;
        drainTicks     <= 0;
        for (Integer i = 0; i < valueOf(ResultOrderDepth); i = i + 1)
            reorderBuf[i] <= OrderedResult { valid: False, pktIdx: 0,
                                             matched: False, ruleId: 0 };
    endmethod

    method Bool canAccept(Bit#(32) pktIdx);
        Bit#(4) slot = truncate(pktIdx);
        return !reorderBuf[slot].valid;
    endmethod

    method Action addResult(Bit#(32) pktIdx, Bool matched, Bit#(16) ruleId);
        Bit#(4) slot = truncate(pktIdx);
        reorderBuf[slot] <= OrderedResult { valid: True, pktIdx: pktIdx,
                                            matched: matched, ruleId: ruleId };
    endmethod

    method Action startWrite(ResultSummary summary)
            if (!done && sumPhase == 0 && processedCount == pktTotal);
        summaryR <= summary;
        sumPhase <= 1;
    endmethod

    method Bool writeDone = done;

    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) writeReq;
        let r = writeReqQ.first; writeReqQ.deq; return r;
    endmethod

    method ActionValue#(Bit#(512)) writeWord;
        let w = writeWordQ.first; writeWordQ.deq; return w;
    endmethod

endmodule

endpackage
