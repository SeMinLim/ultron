package ResultWriter;

// Streams per-packet match results to HBM[2] (port "result") as each packet
// finishes.  No per-packet FIFO: the only buffer is the 16-entry AXI line
// register pktBuf.  On every line boundary (or the last packet) a 64B burst
// is issued.  After all packets complete, startWrite emits a separate 128B
// burst at the base address holding the summary counters.
//
// Result buffer layout (unchanged from host's point of view):
//   [0..128)              128B summary: 32 x u32 counters
//   [128..128+pktCount*4) per-packet: {matched[1], reserved[15], ruleId[16]} per packet

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
} ResultSummary deriving (Bits, Eq, FShow);

interface ResultWriterIfc;
    // Must be called before the first addResult: latches resultBase + pktCount
    // and resets the internal state.
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

    // Summary emission is a small 2-step state machine.  Separating it from
    // startWrite avoids enqueueing two words into writeWordQ in a single action
    // (which would need writeWordQ.notFull to guarantee 2 slots, not 1).
    Reg#(Bit#(2))       sumPhase <- mkReg(0);
    Reg#(ResultSummary) summaryR <- mkReg(unpack(0));

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

    rule emitSummary0(sumPhase == 1);
        writeReqQ.enq(tuple2(resultBase_r, 128));
        writeWordQ.enq(packSummary0(summaryR, matchedCount, processedCount));
        sumPhase <= 2;
    endrule

    rule emitSummary1(sumPhase == 2);
        writeWordQ.enq(packSummary1(summaryR));
        sumPhase <= 0;
        done     <= True;
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
    endmethod

    // Streams one result into pktBuf; flushes a 64B AXI beat on line boundary
    // or on the last packet.  Guard conservatively requires both mem queues to
    // have a free slot so a flush never stalls mid-action.
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
                resultBase_r + 128 + zeroExtend(lineIdx) * 64, 64));
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

    // Only arms the summary emission once every per-packet line has been
    // flushed.  The two emitSummary rules then drive the actual burst.
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
