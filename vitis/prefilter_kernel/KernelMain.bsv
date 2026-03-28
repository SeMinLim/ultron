
package KernelMain;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import BRAM::*;
import BRAMFIFO::*;

import PcieCtrl::*;
import PacketParser::*;
import PacketParserTypes::*;
import FPSM::*;
import RuleReduction::*;
import HeaderMatcher::*;
import TrafficManager::*;
import NFPSM::*;


typedef 2 MemPortCnt;

typedef struct {
    Bit#(64) addr;
    Bit#(32) bytes;
} MemPortReq deriving (Eq, Bits);

interface MemPortIfc;
    method ActionValue#(MemPortReq) readReq;
    method ActionValue#(MemPortReq) writeReq;
    method ActionValue#(Bit#(512))  writeWord;
    method Action                   readWord(Bit#(512) word);
endinterface

interface KernelMainIfc;
    method Action            start(Bit#(32) param);
    method ActionValue#(Bool) done;
    interface Vector#(MemPortCnt, MemPortIfc) mem;
endinterface


typedef enum { IDLE, CFG, PKT, SETTLE, RESULT, RESULT_WRITE }
    KPhase deriving (Eq, Bits);


module mkKernelMain(KernelMainIfc);

    Vector#(MemPortCnt, FIFO#(MemPortReq)) readReqQs  <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(MemPortReq)) writeReqQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512)))  writeWordQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512)))  readWordQs  <- replicateM(mkFIFO);

    Reg#(Bool)     started  <- mkReg(False);
    Reg#(Bit#(32)) paramReg <- mkReg(0);
    FIFO#(Bool)    doneQ    <- mkFIFO;

    Reg#(KPhase)   phase     <- mkReg(IDLE);
    Reg#(Bit#(16)) cfgBlocks <- mkReg(0);
    Reg#(Bit#(16)) pktBlocks <- mkReg(0);

    FIFO#(DMAWord) inputQ  <- mkSizedBRAMFIFO(512);
    FIFO#(DMAWord) outputQ <- mkSizedBRAMFIFO(512);
    FIFO#(Tuple2#(Bit#(128), PacketMeta)) pendingNFPSMFPQ <- mkSizedBRAMFIFO(64);

    Vector#(8, PacketParserIfc)  pes               <- replicateM(mkPacketParser);
    Vector#(8, Reg#(PacketMeta)) lastMeta          <- replicateM(mkRegU);
    Vector#(8, Reg#(Bit#(32)))   metaCount         <- replicateM(mkReg(0));
    Vector#(8, Reg#(Bit#(16)))   currentByteOffset <- replicateM(mkReg(0));
    Vector#(8, Reg#(Bool))       metaReady         <- replicateM(mkReg(False));

    FPSMIfc        fpsm          <- mkFPSM;
    SimpleNFPSMIfc nfpsm_matcher <- mkSimpleNFPSM;
    NFPSMIfc       nfpsm        <- mkNFPSM;

    RuleReductionIfc  ruleReduction <- mkRuleReduction;
    HeaderMatcherIfc  headerMatcher <- mkHeaderMatcher;
    TrafficManagerIfc trafficMgr    <- mkTrafficManager;

    Vector#(8, Reg#(Maybe#(Bit#(128)))) fpsmBuf       <- replicateM(mkReg(tagged Invalid));
    Vector#(8, Reg#(Bit#(256)))         packetFpsmAcc  <- replicateM(mkReg(0));
    Vector#(8, Reg#(Bit#(128)))         packetNFPSMAcc <- replicateM(mkReg(0));

    Reg#(Bit#(256)) fpsmMatchResult   <- mkReg(0);
    Reg#(Bit#(32))  fpsmMatchCount    <- mkReg(0);
    Reg#(Bit#(32))  fpsmTotalMatches  <- mkReg(0);
    Reg#(Bit#(32))  reducedMatchCount <- mkReg(0);
    Reg#(Bit#(32))  headerMatchCount  <- mkReg(0);
    Reg#(Bit#(32))  packetCount       <- mkReg(0);
    Reg#(Bit#(32))  noFpsmCleanCount  <- mkReg(0);

    Reg#(Bit#(3))  inPe             <- mkReg(0);
    Reg#(Bit#(16)) inWordsLeft      <- mkReg(0);
    Reg#(Bit#(3))  outPe            <- mkReg(0);
    Reg#(Bit#(16)) outputCntUp      <- mkReg(0);
    Reg#(Bit#(16)) outputCntDn      <- mkReg(0);
    Reg#(Bit#(3))  dispatchBufCount  <- mkReg(0);
    Reg#(Bit#(3))  dispatchBufOutIdx <- mkReg(4);
    Vector#(4, Reg#(DMAWord)) dispatchBuf <- replicateM(mkRegU);

    Reg#(Bit#(16))             cfgIdx        <- mkReg(0);
    Reg#(Bool)                 cfgReqPending <- mkReg(False);
    Vector#(8, Reg#(Bit#(64))) cfgCmdBuf     <- replicateM(mkReg(0));
    Reg#(Bit#(4))              cfgCmdCount   <- mkReg(0);
    Reg#(Bit#(3))              cfgCmdNext    <- mkReg(0);

    Reg#(Bit#(32)) shMaskHi <- mkReg(0);
    Reg#(Bit#(32)) shMaskLo <- mkReg(0);
    Reg#(Bit#(32)) ckPatHi <- mkReg(0);
    Reg#(Bit#(32)) ckPatLo <- mkReg(0);

    Reg#(Bit#(16))  pktIdx        <- mkReg(0);
    Reg#(Bool)      pktReqPending <- mkReg(False);
    Reg#(Bit#(512)) pktAXIWord   <- mkReg(0);
    Reg#(Bit#(3))   pktDMAIdx    <- mkReg(4);

    Reg#(Bit#(20)) settleCount <- mkReg(0);


    rule systemStart(started && phase == IDLE);
        cfgBlocks    <= paramReg[31:16];
        pktBlocks    <= paramReg[15:0];
        cfgIdx       <= 0;
        cfgReqPending <= False;
        cfgCmdCount  <= 0;
        pktIdx       <= 0;
        pktReqPending <= False;
        pktDMAIdx    <= 4;
        settleCount  <= 0;
        started      <= False;
        if (paramReg[31:16] != 0)
            phase <= CFG;
        else if (paramReg[15:0] != 0)
            phase <= PKT;
        else
            phase <= SETTLE;
    endrule


    rule cfgIssueReq(phase == CFG && !cfgReqPending && cfgCmdCount == 0
                     && cfgIdx < cfgBlocks);
        readReqQs[0].enq(MemPortReq{addr: zeroExtend(cfgIdx) * 64, bytes: 64});
        cfgReqPending <= True;
    endrule

    rule cfgFetch(phase == CFG && cfgReqPending && cfgCmdCount == 0);
        readWordQs[0].deq;
        let w = readWordQs[0].first;
        for (Integer k = 0; k < 8; k = k + 1) begin
            Bit#(512) shifted = w >> fromInteger(64 * k);
            cfgCmdBuf[k] <= truncate(shifted);
        end
        cfgCmdCount   <= 8;
        cfgCmdNext    <= 0;
        cfgIdx        <= cfgIdx + 1;
        cfgReqPending <= False;
    endrule

    rule cfgDispatch(cfgCmdCount > 0);
        Bit#(64) cmd = cfgCmdBuf[cfgCmdNext];
        Bit#(32) off = cmd[63:32];
        Bit#(32) d   = cmd[31:0];

        if      (off == 31) fpsm.loadHTBit(d[11:9], d[8:0]);
        else if (off == 32) ruleReduction.loadCuckooEntry(d[28], d[27:25], d[24:16],
                                                           {ckPatHi, ckPatLo}, d[15:0]);
        else if (off == 33) headerMatcher.stageRulePg(d[31:16], d[15:8], d[7:0]);
        else if (off == 34) headerMatcher.stageSrcPorts(d[31:16], d[15:0]);
        else if (off == 35) headerMatcher.commitDstPorts(d[31:16], d[15:0]);
        else if (off == 36) nfpsm.loadRuleFP(d[24:16], d[10:8], d[15:0]);
        else if (off == 37) nfpsm_matcher.loadBTableEntry(d[15:8], d[7:0]);
        else if (off == 38) nfpsm_matcher.loadHTBit(d[11:9], d[8:0]);
        else if (off == 39) shMaskHi <= d;
        else if (off == 40) shMaskLo <= d;
        else if (off == 41) fpsm.loadShMaskEntry(d[10:8], d[7:0], {shMaskHi, shMaskLo});
        else if (off == 47) fpsm.loadHasPatterns(d[10:8], d[7:0]);
        else if (off == 42) ckPatHi <= d;
        else if (off == 43) ckPatLo <= d;

        cfgCmdNext  <= cfgCmdNext + 1;
        cfgCmdCount <= cfgCmdCount - 1;

        if (cfgIdx == cfgBlocks && cfgCmdCount == 1)
            phase <= (pktBlocks != 0) ? PKT : SETTLE;
    endrule


    rule pktIssueReq(phase == PKT && !pktReqPending && pktDMAIdx == 4
                     && pktIdx < pktBlocks);
        Bit#(64) base = zeroExtend(cfgBlocks) * 64;
        readReqQs[0].enq(MemPortReq{addr: base + zeroExtend(pktIdx) * 64, bytes: 64});
        pktReqPending <= True;
    endrule

    rule pktFetch(phase == PKT && pktReqPending && pktDMAIdx == 4);
        readWordQs[0].deq;
        pktAXIWord    <= readWordQs[0].first;
        pktDMAIdx     <= 0;
        pktIdx        <= pktIdx + 1;
        pktReqPending <= False;
    endrule

    rule pktPush(pktDMAIdx < 4);
        Bit#(128) dmaWord = case (pktDMAIdx)
            3'd0: pktAXIWord[127:0];
            3'd1: pktAXIWord[255:128];
            3'd2: pktAXIWord[383:256];
            3'd3: pktAXIWord[511:384];
            default: 0;
        endcase;
        inputQ.enq(dmaWord);
        Bit#(3) nextIdx = pktDMAIdx + 1;
        pktDMAIdx <= nextIdx;
        if (pktDMAIdx == 3 && pktIdx == pktBlocks)
            phase <= SETTLE;
    endrule


    rule settle(phase == SETTLE);
        settleCount <= settleCount + 1;
        if (settleCount == 20'hFFFFF)
            phase <= RESULT;
    endrule


    rule resultReq(phase == RESULT);
        writeReqQs[1].enq(MemPortReq{addr: 0, bytes: 64});
        phase <= RESULT_WRITE;
    endrule

    rule resultWrite(phase == RESULT_WRITE);
        Bit#(512) stats = 0;
        stats[31:0]    = packetCount;
        stats[63:32]   = noFpsmCleanCount;
        stats[95:64]   = trafficMgr.getNFPSMPackets();
        stats[127:96]  = trafficMgr.getCleanPackets();
        stats[159:128] = nfpsm.getCPUCount();
        stats[191:160] = nfpsm.getCleanCount();
        stats[223:192] = fpsmMatchCount;
        stats[255:224] = fpsmTotalMatches;
        stats[287:256] = reducedMatchCount;
        stats[319:288] = headerMatchCount;
        writeWordQs[1].enq(stats);
        phase <= IDLE;
        doneQ.enq(True);
    endrule


    rule drainOutput;
        outputQ.deq;
    endrule


    rule dispatchBuffer(inWordsLeft == 0 && dispatchBufCount < 4
                        && dispatchBufOutIdx == 4);
        inputQ.deq;
        dispatchBuf[dispatchBufCount] <= inputQ.first;
        dispatchBufCount <= dispatchBufCount + 1;
    endrule

    rule dispatchNewPacket(inWordsLeft == 0 && dispatchBufCount == 4
                           && dispatchBufOutIdx == 4);
        Bit#(16) totalLength  = dispatchBuf[1][127:112];
        Bit#(32) frameLength  = 14 + zeroExtend(totalLength);
        Bit#(32) totalWords32 = (frameLength + 15) >> 4;
        Bit#(16) totalWords   = truncate(totalWords32);
        dispatchBufCount <= 0;
        if (totalLength >= 20) begin
            dispatchBufOutIdx <= 0;
            if (totalWords <= 4) begin
                inWordsLeft <= 0;
                inPe <= inPe + 1;
            end else begin
                inWordsLeft <= totalWords - 4;
            end
        end else begin
            dispatchBufOutIdx <= 4;
        end
    endrule

    rule outputDispatchBuf(dispatchBufOutIdx < 4);
        pes[inPe].enq(dispatchBuf[dispatchBufOutIdx]);
        dispatchBufOutIdx <= dispatchBufOutIdx + 1;
    endrule

    rule dispatchPacket(inWordsLeft > 0 && dispatchBufOutIdx == 4);
        inputQ.deq;
        pes[inPe].enq(inputQ.first);
        if (inWordsLeft == 1) begin
            inWordsLeft <= 0;
            inPe <= inPe + 1;
        end else begin
            inWordsLeft <= inWordsLeft - 1;
        end
    endrule


    rule drainPayload;
        Bit#(3) idx0 = outPe;
        Bit#(3) idx1 = outPe + 1;
        Bit#(3) idx2 = outPe + 2;
        Bit#(3) idx3 = outPe + 3;
        Bit#(3) idx4 = outPe + 4;
        Bit#(3) idx5 = outPe + 5;
        Bit#(3) idx6 = outPe + 6;
        Bit#(3) idx7 = outPe + 7;

        Bit#(3)  selIdx       = idx0;
        Bool     selValid     = False;
        DMAWord  selPayload   = pes[idx0].payloadFirst;
        Bit#(16) selByteStart = currentByteOffset[idx0];
        Bit#(16) selPayloadEnd =
            lastMeta[idx0].payloadOffset + lastMeta[idx0].payloadLength;

        if (pes[idx0].payloadValid && metaReady[idx0]) begin
            selIdx = idx0; selValid = True;
            selPayload    = pes[idx0].payloadFirst;
            selByteStart  = currentByteOffset[idx0];
            selPayloadEnd = lastMeta[idx0].payloadOffset + lastMeta[idx0].payloadLength;
        end else if (pes[idx1].payloadValid && metaReady[idx1]) begin
            selIdx = idx1; selValid = True;
            selPayload    = pes[idx1].payloadFirst;
            selByteStart  = currentByteOffset[idx1];
            selPayloadEnd = lastMeta[idx1].payloadOffset + lastMeta[idx1].payloadLength;
        end else if (pes[idx2].payloadValid && metaReady[idx2]) begin
            selIdx = idx2; selValid = True;
            selPayload    = pes[idx2].payloadFirst;
            selByteStart  = currentByteOffset[idx2];
            selPayloadEnd = lastMeta[idx2].payloadOffset + lastMeta[idx2].payloadLength;
        end else if (pes[idx3].payloadValid && metaReady[idx3]) begin
            selIdx = idx3; selValid = True;
            selPayload    = pes[idx3].payloadFirst;
            selByteStart  = currentByteOffset[idx3];
            selPayloadEnd = lastMeta[idx3].payloadOffset + lastMeta[idx3].payloadLength;
        end else if (pes[idx4].payloadValid && metaReady[idx4]) begin
            selIdx = idx4; selValid = True;
            selPayload    = pes[idx4].payloadFirst;
            selByteStart  = currentByteOffset[idx4];
            selPayloadEnd = lastMeta[idx4].payloadOffset + lastMeta[idx4].payloadLength;
        end else if (pes[idx5].payloadValid && metaReady[idx5]) begin
            selIdx = idx5; selValid = True;
            selPayload    = pes[idx5].payloadFirst;
            selByteStart  = currentByteOffset[idx5];
            selPayloadEnd = lastMeta[idx5].payloadOffset + lastMeta[idx5].payloadLength;
        end else if (pes[idx6].payloadValid && metaReady[idx6]) begin
            selIdx = idx6; selValid = True;
            selPayload    = pes[idx6].payloadFirst;
            selByteStart  = currentByteOffset[idx6];
            selPayloadEnd = lastMeta[idx6].payloadOffset + lastMeta[idx6].payloadLength;
        end else if (pes[idx7].payloadValid && metaReady[idx7]) begin
            selIdx = idx7; selValid = True;
            selPayload    = pes[idx7].payloadFirst;
            selByteStart  = currentByteOffset[idx7];
            selPayloadEnd = lastMeta[idx7].payloadOffset + lastMeta[idx7].payloadLength;
        end

        if (selValid) begin
            Bit#(16) byteEnd    = selByteStart + 16;
            PacketMeta activeMeta = lastMeta[selIdx];

            Bool inPayload =
                (byteEnd > activeMeta.payloadOffset)
                && (selByteStart < selPayloadEnd)
                && (activeMeta.payloadLength > 0);
            Bool isLastPayloadWord = inPayload && (byteEnd >= selPayloadEnd);

            outputQ.enq(selPayload);
            pes[selIdx].payloadDeq;
            outPe      <= selIdx + 1;
            outputCntUp <= outputCntUp + 1;

            Bool hasBuf   = isValid(fpsmBuf[selIdx]);
            Bit#(128) fpsm_lo = hasBuf ? fromMaybe(0, fpsmBuf[selIdx]) : selPayload;
            Bit#(128) fpsm_hi = hasBuf ? selPayload                     : 128'h0;

            Vector#(OutputSize, Bool) fpsmMatches = fpsm.process({fpsm_hi, fpsm_lo});
            Bit#(256) chunkBits    = pack(fpsmMatches);
            Bit#(128) nfpsmChunk   = nfpsm_matcher.process({fpsm_hi, fpsm_lo});

            if (inPayload && !isLastPayloadWord) begin
                if (!hasBuf) begin
                    fpsmBuf[selIdx] <= tagged Valid selPayload;
                end else begin
                    if (chunkBits != 0) begin
                        fpsmMatchCount   <= fpsmMatchCount + 1;
                        fpsmTotalMatches <= fpsmTotalMatches + countMatches(fpsmMatches);
                        ruleReduction.putWindow(chunkBits, {fpsm_hi, fpsm_lo},
                                                activeMeta, False);
                    end
                    packetFpsmAcc[selIdx]  <= packetFpsmAcc[selIdx]  | chunkBits;
                    packetNFPSMAcc[selIdx] <= packetNFPSMAcc[selIdx] | nfpsmChunk;
                    fpsmBuf[selIdx]        <= tagged Valid selPayload;
                end
            end

            currentByteOffset[selIdx] <= (byteEnd >= selPayloadEnd) ? 0 : byteEnd;

            if (byteEnd >= selPayloadEnd) begin
                Bit#(256) lastBits    = inPayload ? chunkBits  : 0;
                Bit#(128) lastNFPSM   = inPayload ? nfpsmChunk : 0;
                Bit#(256) totalAcc    = packetFpsmAcc[selIdx]  | lastBits;
                Bit#(128) totalNFPSMAcc = packetNFPSMAcc[selIdx] | lastNFPSM;

                if (inPayload && chunkBits != 0) begin
                    fpsmMatchCount   <= fpsmMatchCount + 1;
                    fpsmTotalMatches <= fpsmTotalMatches + countMatches(fpsmMatches);
                end

                if (totalAcc != 0) fpsmMatchResult <= totalAcc;

                Bit#(32) reducedCount = reduceMatchCount(unpack(totalAcc));
                reducedMatchCount <= reducedMatchCount + reducedCount;

                if (activeMeta.totalLength >= 20)
                    packetCount <= packetCount + 1;
                if (activeMeta.totalLength >= 20) begin
                    if (totalAcc != 0) begin
                        ruleReduction.putWindow(lastBits, {fpsm_hi, fpsm_lo},
                                                activeMeta, True);
                        pendingNFPSMFPQ.enq(tuple2(totalNFPSMAcc, activeMeta));
                    end else begin
                        noFpsmCleanCount <= noFpsmCleanCount + 1;
                    end
                end

                packetFpsmAcc[selIdx]  <= 0;
                packetNFPSMAcc[selIdx] <= 0;
                fpsmBuf[selIdx]        <= tagged Invalid;
                metaReady[selIdx]      <= False;
            end
        end
    endrule


    rule connectRuleReductionToHeaderMatcher(ruleReduction.outValid);
        let ruleIds = ruleReduction.outRuleIds;
        let meta    = ruleReduction.outMeta;
        ruleReduction.outDeq;
        headerMatcher.put(ruleIds, meta);
    endrule

    rule connectHeaderMatcherToTrafficMgr(headerMatcher.outValid);
        let results = headerMatcher.outResults;
        let meta    = headerMatcher.outMeta;
        headerMatcher.outDeq;
        Bool anyValid = False;
        for (Integer i = 0; i < 8; i = i + 1)
            if (results[i].valid) anyValid = True;
        if (anyValid) headerMatchCount <= headerMatchCount + 1;
        trafficMgr.putHeaderResults(results, meta);
    endrule

    rule drainTrafficDecision;
        match {.decision, .meta} <- trafficMgr.getDecision();
        let pending = pendingNFPSMFPQ.first;
        pendingNFPSMFPQ.deq;
        let pktFP   = tpl_1(pending);
        let pktMeta = tpl_2(pending);
        Vector#(MaxCandidates, Maybe#(Bit#(16))) ruleIds = replicate(tagged Invalid);
        Bit#(4) numRules = zeroExtend(decision.numRules);
        for (Integer i = 0; i < 8; i = i + 1) begin
            Bit#(4) idx = fromInteger(i);
            if (idx < numRules)
                ruleIds[i] = tagged Valid decision.ruleIds[i];
        end
        if (decision.needsNFPSM)
            nfpsm.putSuspicious(pktFP, ruleIds, pktMeta);
    endrule

    rule drainNFPSM(nfpsm.outValid);
        nfpsm.outDeq;
    endrule


    (* descending_urgency = "drainMeta0, drainMeta1, drainMeta2, drainMeta3, drainMeta4, drainMeta5, drainMeta6, drainMeta7, drainPayload" *)
    rule drainMeta0(pes[0].metaValid && !metaReady[0]);
        let m = pes[0].metaFirst; pes[0].metaDeq;
        lastMeta[0] <= m; metaCount[0] <= metaCount[0] + 1;
        metaReady[0] <= True;
    endrule
    rule drainMeta1(pes[1].metaValid && !metaReady[1]);
        let m = pes[1].metaFirst; pes[1].metaDeq;
        lastMeta[1] <= m; metaCount[1] <= metaCount[1] + 1;
        metaReady[1] <= True;
    endrule
    rule drainMeta2(pes[2].metaValid && !metaReady[2]);
        let m = pes[2].metaFirst; pes[2].metaDeq;
        lastMeta[2] <= m; metaCount[2] <= metaCount[2] + 1;
        metaReady[2] <= True;
    endrule
    rule drainMeta3(pes[3].metaValid && !metaReady[3]);
        let m = pes[3].metaFirst; pes[3].metaDeq;
        lastMeta[3] <= m; metaCount[3] <= metaCount[3] + 1;
        metaReady[3] <= True;
    endrule
    rule drainMeta4(pes[4].metaValid && !metaReady[4]);
        let m = pes[4].metaFirst; pes[4].metaDeq;
        lastMeta[4] <= m; metaCount[4] <= metaCount[4] + 1;
        metaReady[4] <= True;
    endrule
    rule drainMeta5(pes[5].metaValid && !metaReady[5]);
        let m = pes[5].metaFirst; pes[5].metaDeq;
        lastMeta[5] <= m; metaCount[5] <= metaCount[5] + 1;
        metaReady[5] <= True;
    endrule
    rule drainMeta6(pes[6].metaValid && !metaReady[6]);
        let m = pes[6].metaFirst; pes[6].metaDeq;
        lastMeta[6] <= m; metaCount[6] <= metaCount[6] + 1;
        metaReady[6] <= True;
    endrule
    rule drainMeta7(pes[7].metaValid && !metaReady[7]);
        let m = pes[7].metaFirst; pes[7].metaDeq;
        lastMeta[7] <= m; metaCount[7] <= metaCount[7] + 1;
        metaReady[7] <= True;
    endrule


    Vector#(MemPortCnt, MemPortIfc) mem_;
    for (Integer i = 0; i < valueOf(MemPortCnt); i = i + 1) begin
        mem_[i] = interface MemPortIfc;
            method ActionValue#(MemPortReq) readReq;
                readReqQs[i].deq;
                return readReqQs[i].first;
            endmethod
            method ActionValue#(MemPortReq) writeReq;
                writeReqQs[i].deq;
                return writeReqQs[i].first;
            endmethod
            method ActionValue#(Bit#(512)) writeWord;
                writeWordQs[i].deq;
                return writeWordQs[i].first;
            endmethod
            method Action readWord(Bit#(512) word);
                readWordQs[i].enq(word);
            endmethod
        endinterface;
    end

    method Action start(Bit#(32) param) if (!started && phase == IDLE);
        paramReg <= param;
        started  <= True;
    endmethod

    method ActionValue#(Bool) done;
        doneQ.deq;
        return doneQ.first;
    endmethod

    interface mem = mem_;

endmodule

endpackage: KernelMain
