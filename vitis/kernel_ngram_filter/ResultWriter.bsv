package ResultWriter;

// Collects per-packet match results, then writes a result buffer to HBM[2] (port "result").
//
// Result buffer layout:
//   [0..128)              128B summary: 32 x u32 counters
//   [128..128+pktCount×4) per-packet: {matched[1], reserved[15], ruleId[16]} per packet

import FIFO::*;
import FIFOF::*;
import Vector::*;

interface ResultWriterIfc;
    method Action addResult(Bool matched, Bit#(16) ruleId);
    method Action startWrite(Bit#(64) resultBase, Bit#(32) pktCount,
                             ResultSummary summary);
    method Bool   writeDone;
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) writeReq;
    method ActionValue#(Bit#(512)) writeWord;
endinterface

typedef struct {
    Bit#(32) dbCycles;
    Bit#(32) pktCycles;
    Bit#(32) totalCycles;
    Bit#(32) dataLoaderCycles;
    Bit#(32) packetReaderCycles;
    Bit#(32) packetParserCycles;
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
} ResultSummary deriving (Bits, Eq, FShow);

module mkResultWriter(ResultWriterIfc);

    FIFOF#(Tuple2#(Bool, Bit#(16))) resultsQ <- mkSizedFIFOF(4096);

    FIFOF#(Tuple2#(Bit#(64), Bit#(64))) writeReqQ <- mkFIFOF;
    FIFOF#(Bit#(512))                   writeWordQ <- mkSizedFIFOF(8);

    Reg#(Bit#(32)) matchedCount  <- mkReg(0);
    Reg#(Bit#(32)) processedCount<- mkReg(0);

    Reg#(Bool)     writing       <- mkReg(False);
    Reg#(Bool)     done          <- mkReg(False);
    Reg#(Bit#(64)) resultBase_r  <- mkRegU;
    Reg#(Bit#(32)) pktTotal      <- mkReg(0);
    Reg#(Bit#(2))  summaryWordsLeft <- mkReg(0);
    Reg#(Bit#(32)) wordsLeft     <- mkReg(0);  // per-packet words to write
    Reg#(ResultSummary) summaryR <- mkReg(unpack(0));

    Reg#(Vector#(16, Bit#(32))) pktBuf   <- mkReg(replicate(0));
    Reg#(Bit#(5))               pktBufN  <- mkReg(0);
    Reg#(Bit#(32))              pktsDone <- mkReg(0);

    rule writeSummary0(writing && summaryWordsLeft == 2 && !done && writeWordQ.notFull);
        Bit#(512) sumWord = 0;
        sumWord[31:0]    = matchedCount;
        sumWord[63:32]   = processedCount;
        sumWord[95:64]   = summaryR.dbCycles;
        sumWord[127:96]  = summaryR.pktCycles;
        sumWord[159:128] = summaryR.totalCycles;
        sumWord[191:160] = summaryR.dataLoaderCycles;
        sumWord[223:192] = summaryR.packetReaderCycles;
        sumWord[255:224] = summaryR.packetParserCycles;
        sumWord[287:256] = summaryR.ngramCycles;
        sumWord[319:288] = summaryR.bitmapCycles;
        sumWord[351:320] = summaryR.gramCycles;
        sumWord[383:352] = summaryR.exactCycles;
        sumWord[415:384] = summaryR.pomCycles;
        sumWord[447:416] = summaryR.resultWriterCycles;
        sumWord[479:448] = summaryR.gramsExtracted;
        sumWord[511:480] = summaryR.bitmapPassed;
        writeWordQ.enq(sumWord);
        summaryWordsLeft <= 1;
    endrule

    rule writeSummary1(writing && summaryWordsLeft == 1 && !done && writeWordQ.notFull);
        Bit#(512) sumWord = 0;
        sumWord[31:0]    = summaryR.gramLookups;
        sumWord[63:32]   = summaryR.gramHits;
        sumWord[95:64]   = summaryR.exactChecks;
        sumWord[127:96]  = summaryR.exactHits;
        sumWord[159:128] = summaryR.exactMisses;
        sumWord[191:160] = summaryR.pomChecks;
        sumWord[223:192] = summaryR.pomHits;
        sumWord[255:224] = summaryR.pomMisses;
        sumWord[287:256] = summaryR.noMatchPkts;
        writeWordQ.enq(sumWord);
        summaryWordsLeft <= 0;
        wordsLeft <= (pktTotal + 15) / 16;
        pktsDone  <= 0;
        pktBufN   <= 0;
        pktBuf    <= replicate(0);
    endrule

    rule writePerPkt(writing && summaryWordsLeft == 0 && wordsLeft > 0 && resultsQ.notEmpty);
        let {matched, ruleId} = resultsQ.first; resultsQ.deq;
        Bit#(32) entry = {matched ? 1'b1 : 1'b0, 15'b0, ruleId};
        Vector#(16, Bit#(32)) pktVec = pktBuf;
        pktVec[pktBufN] = entry;
        pktsDone<= pktsDone + 1;

        if (pktBufN == 15 || pktsDone + 1 >= pktTotal) begin
            writeWordQ.enq(pack(pktVec));
            pktBuf   <= replicate(0);
            pktBufN  <= 0;
            wordsLeft<= wordsLeft - 1;
            if (pktsDone + 1 >= pktTotal) begin
                done    <= True;
                writing <= False;
            end
        end else begin
            pktBuf <= pktVec;
            pktBufN <= pktBufN + 1;
        end
    endrule

    method Action addResult(Bool matched, Bit#(16) ruleId) if (resultsQ.notFull);
        resultsQ.enq(tuple2(matched, ruleId));
        processedCount <= processedCount + 1;
        if (matched) matchedCount <= matchedCount + 1;
    endmethod

    method Action startWrite(Bit#(64) resultBase, Bit#(32) pktCount,
                             ResultSummary summary)
            if (!writing && !done);
        resultBase_r  <= resultBase;
        pktTotal      <= pktCount;
        summaryR      <= summary;
        Bit#(64) totalBytes = 128 + zeroExtend((pktCount + 15) / 16) * 64;
        writeReqQ.enq(tuple2(resultBase, totalBytes));
        writing   <= True;
        done      <= False;
        summaryWordsLeft <= 2;
        wordsLeft <= 0;
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
