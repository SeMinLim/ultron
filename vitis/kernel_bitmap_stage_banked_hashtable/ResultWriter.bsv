package ResultWriter;

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
    method Action addResult(Bool matched, Bit#(16) ruleId);
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
    Reg#(Bit#(32)) pktsDone       <- mkReg(0);
    Reg#(Bit#(32)) lineIdx        <- mkReg(0);

    Reg#(Vector#(16, Bit#(32))) pktBuf  <- mkReg(replicate(0));
    Reg#(Bit#(5))               pktBufN <- mkReg(0);

    Reg#(Bit#(2))       sumPhase <- mkReg(0);
    Reg#(ResultSummary) summaryR <- mkReg(unpack(0));

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
        pktsDone       <= 0;
        lineIdx        <= 0;
        pktBuf         <= replicate(0);
        pktBufN        <= 0;
        sumPhase       <= 0;
        drainTicks     <= 0;
    endmethod

    method Action addResult(Bool matched, Bit#(16) ruleId)
            if (pktsDone < pktTotal &&
                writeReqQ.notFull && writeWordQ.notFull);
        Bit#(32) entry = {pack(matched), 15'b0, ruleId};
        Vector#(16, Bit#(32)) v = pktBuf;
        v[pktBufN] = entry;

        processedCount <= processedCount + 1;
        if (matched) matchedCount <= matchedCount + 1;

        Bool isLastPkt = (pktsDone + 1 == pktTotal);
        Bool flushLine = (pktBufN == 15) || isLastPkt;

        if (flushLine) begin
            writeReqQ.enq(tuple2(
                resultBase_r + 192 + zeroExtend(lineIdx) * 64, 64));
            writeWordQ.enq(pack(v));
            pktBuf  <= replicate(0);
            pktBufN <= 0;
            lineIdx <= lineIdx + 1;
        end else begin
            pktBuf  <= v;
            pktBufN <= pktBufN + 1;
        end
        pktsDone <= pktsDone + 1;
    endmethod

    method Action startWrite(ResultSummary summary)
            if (!done && sumPhase == 0 &&
                pktsDone == pktTotal && pktBufN == 0);
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
