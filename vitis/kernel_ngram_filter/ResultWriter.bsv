package ResultWriter;

// Collects per-packet match results, then writes a result buffer to HBM[2] (port "result").
//
// Result buffer layout:
//   [0..64)               64B summary: {total_matched:u32, total_processed:u32,
//                                       db_cycles:u32, pkt_cycles:u32, total_cycles:u32, reserved}
//   [64..64+pktCount×4)   per-packet: {matched[1], reserved[15], ruleId[16]} per packet

import FIFO::*;
import FIFOF::*;
import Vector::*;

interface ResultWriterIfc;
    method Action addResult(Bool matched, Bit#(16) ruleId);
    method Action startWrite(Bit#(64) resultBase, Bit#(32) pktCount,
                             Bit#(32) dbCycles, Bit#(32) pktCycles, Bit#(32) totalCycles);
    method Bool   writeDone;
    // AXI write port (wired to mem port 2)
    method ActionValue#(Tuple2#(Bit#(64), Bit#(64))) writeReq;
    method ActionValue#(Bit#(512)) writeWord;
endinterface

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
    Reg#(Bit#(32)) wordsLeft     <- mkReg(0);  // per-packet words to write
    Reg#(Bit#(32)) tDbCycles     <- mkReg(0);
    Reg#(Bit#(32)) tPktCycles    <- mkReg(0);
    Reg#(Bit#(32)) tTotalCycles  <- mkReg(0);

    // Pack 16 × 32-bit per-packet entries into 512-bit words
    Reg#(Vector#(16, Bit#(32))) pktBuf   <- mkReg(replicate(0));
    Reg#(Bit#(5))               pktBufN  <- mkReg(0);  // entries in pktBuf
    Reg#(Bit#(32))              pktsDone <- mkReg(0);   // packets written

    // Summary word built from matchedCount / processedCount and timing
    rule writeSummary(writing && wordsLeft == 0 && !done && writeWordQ.notFull);
        Bit#(512) sumWord = 0;
        sumWord[31:0]   = matchedCount;
        sumWord[63:32]  = processedCount;
        sumWord[95:64]  = tDbCycles;
        sumWord[127:96] = tPktCycles;
        sumWord[159:128] = tTotalCycles;
        writeWordQ.enq(sumWord);
        wordsLeft <= (pktTotal + 15) / 16;  // ceiling div: per-packet words
        pktsDone  <= 0;
        pktBufN   <= 0;
        pktBuf    <= replicate(0);
    endrule

    rule writePerPkt(writing && wordsLeft > 0 && resultsQ.notEmpty);
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
                             Bit#(32) dbCycles, Bit#(32) pktCycles, Bit#(32) totalCycles)
            if (!writing && !done);
        resultBase_r  <= resultBase;
        pktTotal      <= pktCount;
        tDbCycles     <= dbCycles;
        tPktCycles    <= pktCycles;
        tTotalCycles  <= totalCycles;
        // Issue write request: 64B summary + pktCount × 4B (padded to 64B boundary)
        Bit#(64) totalBytes = 64 + zeroExtend((pktCount + 15) / 16) * 64;
        writeReqQ.enq(tuple2(resultBase, totalBytes));
        writing   <= True;
        done      <= False;
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
