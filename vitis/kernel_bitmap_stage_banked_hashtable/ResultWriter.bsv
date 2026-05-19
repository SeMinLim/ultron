package ResultWriter;

// Result buffer: [0..192) summary, 48 x u32 counters.

import FIFOF::*;

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

module mkResultWriter(ResultWriterIfc);

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) writeReqQ  <- mkFIFOF;
    FIFOF#(Bit#(512))                   writeWordQ <- mkSizedFIFOF(8);

    Reg#(Bit#(32)) matchedCount   <- mkReg(0);
    Reg#(Bit#(32)) processedCount <- mkReg(0);

    Reg#(Bool)     done           <- mkReg(False);
    Reg#(Bit#(64)) resultBase_r   <- mkReg(0);
    Reg#(Bit#(32)) pktTotal       <- mkReg(0);

    Reg#(Bit#(2))       sumPhase <- mkReg(0);
    Reg#(ResultSummary) summaryR <- mkReg(unpack(0));
    // Done is delayed until the summary burst has drained to DDR.
    Reg#(Bit#(8)) drainTicks <- mkReg(0);

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

    rule emitSummary0(sumPhase == 1);
        writeReqQ.enq(tuple2(resultBase_r, 192));
        writeWordQ.enq(packSummary0(summaryR, matchedCount, processedCount));
        sumPhase <= 2;
    endrule

    rule emitSummary1(sumPhase == 2);
        writeWordQ.enq(packSummary1(summaryR));
        sumPhase <= 3;
    endrule

    rule emitSummary2(sumPhase == 3);
        writeWordQ.enq(packSummary2(summaryR));
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
        done           <= False;
        sumPhase       <= 0;
        drainTicks     <= 0;
    endmethod

    method Bool canAccept(Bit#(32) pktIdx);
        return True;
    endmethod

    method Action addResult(Bit#(32) pktIdx, Bool matched, Bit#(16) ruleId);
        processedCount <= processedCount + 1;
        if (matched)
            matchedCount <= matchedCount + 1;
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
