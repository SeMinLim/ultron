import FIFO::*;
import FIFOF::*;
import Clocks::*;
import Vector::*;
import BRAM::*;
import BRAMFIFO::*;

import PcieCtrl::*;
import SimplePacketParser::*;
import PacketParserTypes::*;
import FPSM::*;
import RuleReduction::*;
import HeaderMatcher::*;
	import TrafficManager::*;
import NFPSM::*;

interface HwMainIfc;
endinterface

module mkHwMain#(PcieUserIfc pcie)
	(HwMainIfc);

	Clock curClk <- exposeCurrentClock;
	Reset curRst <- exposeCurrentReset;

	Clock pcieclk = pcie.user_clk;
	Reset pcierst = pcie.user_rst;

	FIFO#(DMAWord) inputQ  <- mkSizedBRAMFIFO(512);
	FIFO#(DMAWord) outputQ <- mkSizedBRAMFIFO(512);
	FIFO#(Tuple2#(Bit#(128), PacketMeta)) pendingNFPSMFPQ <- mkSizedBRAMFIFO(64);
	Reg#(Bit#(16)) outputCntUp <- mkReg(0);
	Reg#(Bit#(16)) outputCntDn <- mkReg(0);

	Vector#(8, PacketParserIfc) pes <- replicateM(mkSimplePacketParser);
	Vector#(8, Reg#(PacketMeta)) lastMeta <- replicateM(mkRegU);
	Vector#(8, Reg#(Bit#(32))) metaCount  <- replicateM(mkReg(0));
	Vector#(8, Reg#(Bit#(16))) currentByteOffset <- replicateM(mkReg(0));
	Vector#(8, Reg#(Bool))     metaReady  <- replicateM(mkReg(False));

	FPSMIfc fpsm <- mkFPSM;

	Reg#(Bit#(256)) fpsmMatchResult  <- mkReg(0);
	Reg#(Bit#(32))  fpsmMatchCount   <- mkReg(0);
	Reg#(Bit#(32))  fpsmTotalMatches <- mkReg(0);

	Reg#(Bit#(32)) reducedMatchCount <- mkReg(0);
	Reg#(Bit#(32)) headerMatchCount  <- mkReg(0);
	Reg#(Bit#(32)) packetCount       <- mkReg(0);
	Reg#(Bit#(32)) noFpsmCleanCount  <- mkReg(0);

	RuleReductionIfc ruleReduction <- mkRuleReduction;

		HeaderMatcherIfc headerMatcher <- mkHeaderMatcher;

		TrafficManagerIfc trafficMgr <- mkTrafficManager;

		SimpleNFPSMIfc nfpsm_matcher <- mkSimpleNFPSM;
		NFPSMIfc       nfpsm         <- mkNFPSM;

	Vector#(8, Reg#(Maybe#(Bit#(128)))) fpsmBuf
		<- replicateM(mkReg(tagged Invalid));
	Vector#(8, Reg#(Bit#(256))) packetFpsmAcc
		<- replicateM(mkReg(0));
	Vector#(8, Reg#(Bit#(128))) packetNFPSMAcc
		<- replicateM(mkReg(0));

	Reg#(Bit#(3)) inPe  <- mkReg(0);
	Reg#(Bit#(16)) inWordsLeft    <- mkReg(0);
	Reg#(Bit#(3)) outPe <- mkReg(0);
	Reg#(Bit#(3)) dispatchBufCount  <- mkReg(0);
	Reg#(Bit#(3)) dispatchBufOutIdx <- mkReg(4);
	Vector#(4, Reg#(DMAWord)) dispatchBuf <- replicateM(mkRegU);

	rule dispatchBuffer(inWordsLeft == 0 && dispatchBufCount < 4
	                    && dispatchBufOutIdx == 4);
		inputQ.deq;
		dispatchBuf[dispatchBufCount] <= inputQ.first;
		dispatchBufCount <= dispatchBufCount + 1;
	endrule

	rule dispatchNewPacket(inWordsLeft == 0 && dispatchBufCount == 4
	                       && dispatchBufOutIdx == 4);
		Bit#(16) totalLength = dispatchBuf[1][127:112];
		Bit#(32) frameLength = 14 + zeroExtend(totalLength);
		Bit#(32) totalWords32 = (frameLength + 15) >> 4;
		Bit#(16) totalWords = truncate(totalWords32);

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

	(* descending_urgency = "drainMeta0, drainMeta1, drainMeta2, drainMeta3, drainMeta4, drainMeta5, drainMeta6, drainMeta7, drainPayload" *)
	rule drainPayload;
		Bit#(3) idx0 = outPe;
		Bit#(3) idx1 = outPe + 1;
		Bit#(3) idx2 = outPe + 2;
		Bit#(3) idx3 = outPe + 3;
		Bit#(3) idx4 = outPe + 4;
		Bit#(3) idx5 = outPe + 5;
		Bit#(3) idx6 = outPe + 6;
		Bit#(3) idx7 = outPe + 7;

		Bit#(3) selIdx = idx0;
		Bool selValid = False;
		DMAWord selPayload = pes[idx0].payloadFirst;
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
			Bit#(16) byteEnd = selByteStart + 16;
			PacketMeta activeMeta = lastMeta[selIdx];

			Bool inPayload =
				(byteEnd > activeMeta.payloadOffset)
				&& (selByteStart < selPayloadEnd)
				&& (activeMeta.payloadLength > 0);
			Bool isLastPayloadWord = inPayload && (byteEnd >= selPayloadEnd);

			outputQ.enq(selPayload);
			pes[selIdx].payloadDeq;
			outPe <= selIdx + 1;
			outputCntUp <= outputCntUp + 1;

			Bool hasBuf = isValid(fpsmBuf[selIdx]);
			Bit#(128) fpsm_lo = hasBuf ? fromMaybe(0, fpsmBuf[selIdx]) : selPayload;
			Bit#(128) fpsm_hi = hasBuf ? selPayload                     : 128'h0;

			Vector#(OutputSize, Bool) fpsmMatches = fpsm.process({fpsm_hi, fpsm_lo});
			Bit#(256) chunkBits = pack(fpsmMatches);
			Bit#(128) nfpsmChunkBits = nfpsm_matcher.process({fpsm_hi, fpsm_lo});

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
					packetNFPSMAcc[selIdx] <= packetNFPSMAcc[selIdx] | nfpsmChunkBits;
					fpsmBuf[selIdx] <= tagged Valid selPayload;
				end
			end

			currentByteOffset[selIdx] <= (byteEnd >= selPayloadEnd) ? 0 : byteEnd;

			if (byteEnd >= selPayloadEnd) begin

				Bit#(256) lastBits      = inPayload ? chunkBits      : 0;
				Bit#(128) lastNFPSMBits = inPayload ? nfpsmChunkBits : 0;
				Bit#(256) totalAcc      = packetFpsmAcc[selIdx]  | lastBits;
				Bit#(128) totalNFPSMAcc = packetNFPSMAcc[selIdx] | lastNFPSMBits;

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
				metaReady[selIdx]         <= False;
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
			if (results[i].valid) begin
				anyValid = True;
			end
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

	BRAM2Port#(Bit#(6),DMAWord) page <- mkBRAM2Server(defaultValue);
	FIFO#(Bit#(8)) streamReadQ  <- mkSizedBRAMFIFO(1024);
	FIFO#(Bit#(8)) streamWriteQ <- mkSizedBRAMFIFO(1024);
	Reg#(Bit#(32)) streamReadCnt  <- mkReg(0);
	Reg#(Bit#(32)) streamWriteCnt <- mkReg(0);

	Reg#(Bit#(32)) soPatHi <- mkReg(0);
	Reg#(Bit#(32)) soPatLo <- mkReg(0);

	Reg#(Bit#(32)) ckPatHi <- mkReg(0);
	Reg#(Bit#(32)) ckPatLo <- mkReg(0);


	rule getCmd;
		let w <- pcie.dataReceive;
		let a = w.addr;
		let d = w.data;
		let off = (a >> 2);
		if      (off == 0)  streamReadQ.enq(truncate(d));
		else if (off == 1)  streamWriteQ.enq(truncate(d));
		else if (off == 31) fpsm.loadHTBit(d[11:9], d[8:0]);
		else if (off == 39) soPatHi <= d;
		else if (off == 40) soPatLo <= d;
		else if (off == 41) fpsm.loadSOPattern({soPatHi, soPatLo}, d[5:3], d[2:0]);

		else if (off == 42) ckPatHi <= d;
		else if (off == 43) ckPatLo <= d;
		else if (off == 32) ruleReduction.loadCuckooEntry(d[28], d[27:25], d[24:16],
		                                                   {ckPatHi, ckPatLo}, d[15:0]);

		else if (off == 33) headerMatcher.stageRulePg(d[31:16], d[15:8], d[7:0]);
		else if (off == 34) headerMatcher.stageSrcPorts(d[31:16], d[15:0]);
		else if (off == 35) headerMatcher.commitDstPorts(d[31:16], d[15:0]);

		else if (off == 36) nfpsm.loadRuleFP(d[24:16], d[10:8], d[15:0]);

		else if (off == 37) nfpsm_matcher.loadBTableEntry(d[15:8], d[7:0]);
		else if (off == 38) nfpsm_matcher.loadHTBit(d[11:9], d[8:0]);
	endrule

	FIFO#(IOReadReq) reqQ <- mkFIFO;
	rule readStat;
		let r <- pcie.dataReq;
		let offset = (r.addr >> 2);
		if      (offset == 0)  pcie.dataSend(r, streamReadCnt);
		else if (offset == 1)  pcie.dataSend(r, streamWriteCnt);
		else if (offset == 2)  pcie.dataSend(r, truncate(fpsmMatchResult));
		else if (offset == 3)  pcie.dataSend(r, truncate(fpsmMatchResult >> 32));
		else if (offset == 4)  pcie.dataSend(r, truncate(fpsmMatchResult >> 64));
		else if (offset == 5)  pcie.dataSend(r, truncate(fpsmMatchResult >> 96));
		else if (offset == 6)  pcie.dataSend(r, truncate(fpsmMatchResult >> 128));
		else if (offset == 7)  pcie.dataSend(r, truncate(fpsmMatchResult >> 160));
		else if (offset == 8)  pcie.dataSend(r, truncate(fpsmMatchResult >> 192));
		else if (offset == 9)  pcie.dataSend(r, truncate(fpsmMatchResult >> 224));
		else if (offset == 10) pcie.dataSend(r, fpsmMatchCount);
		else if (offset == 11) pcie.dataSend(r, fpsmTotalMatches);
		else if (offset == 12) pcie.dataSend(r, reducedMatchCount);
		else if (offset == 13) pcie.dataSend(r, trafficMgr.getNFPSMPackets());
		else if (offset == 14) pcie.dataSend(r, nfpsm.getCleanCount());
		else if (offset == 15) pcie.dataSend(r, nfpsm.getCPUCount());
		else if (offset == 16) pcie.dataSend(r, packetCount);
		else if (offset == 17) pcie.dataSend(r, noFpsmCleanCount);
		else if (offset == 18) pcie.dataSend(r, trafficMgr.getCleanPackets());

		else if (offset == 20) pcie.dataSend(r, metaCount[0]);
		else if (offset == 21) pcie.dataSend(r, metaCount[1]);
		else if (offset == 22) pcie.dataSend(r, metaCount[2]);
		else if (offset == 23) pcie.dataSend(r, metaCount[3]);
		else if (offset == 24) pcie.dataSend(r, metaCount[4]);
		else if (offset == 25) pcie.dataSend(r, metaCount[5]);
		else if (offset == 26) pcie.dataSend(r, metaCount[6]);
		else if (offset == 27) pcie.dataSend(r, metaCount[7]);
		else if (offset == 28) pcie.dataSend(r, zeroExtend(fpsm.soBitmap));
		else if (offset >= 18) begin
			page.portB.request.put(BRAMRequest{
				write: False, responseOnWrite: False,
				address: truncate(offset), datain: ?});
			reqQ.enq(r);
		end else begin
			pcie.dataSend(r, 32'hcccccccc);
		end
	endrule

	rule relayPageRead;
		let r <- page.portB.response.get();
		let req = reqQ.first; reqQ.deq;
		pcie.dataSend(req, truncate(r));
	endrule

	rule dmaReadReq;
		streamReadQ.deq;
		let poff = streamReadQ.first;
		pcie.dmaReadReq((zeroExtend(poff) << 10), 64);
		streamReadCnt <= streamReadCnt + 1;
	endrule

	Reg#(Bit#(32)) dmaReadWords <- mkReg(0);
	rule dmaReadDatal;
		DMAWord rd <- pcie.dmaReadWord;
		page.portA.request.put(BRAMRequest{
			write: True, responseOnWrite: False,
			address: truncate(dmaReadWords), datain: rd});
		dmaReadWords <= dmaReadWords + 1;
		inputQ.enq(rd);
	endrule

	Reg#(Bit#(16)) curOutLeftUp <- mkReg(0);
	Reg#(Bit#(16)) curOutLeftDn <- mkReg(0);
	rule dmaWriteReq(outputCntUp - outputCntDn >= 64
	                 && curOutLeftUp - curOutLeftDn < 128);
		streamWriteQ.deq;
		let woff = streamWriteQ.first;
		pcie.dmaWriteReq((zeroExtend(woff) << 10), 64);
		curOutLeftUp <= curOutLeftUp + 64;
		outputCntDn  <= outputCntDn  + 64;
		streamWriteCnt <= streamWriteCnt + 1;
	endrule

	rule dmaWriteData(curOutLeftUp != curOutLeftDn);
		curOutLeftDn <= curOutLeftDn + 1;
		outputQ.deq;
		pcie.dmaWriteData(outputQ.first);
	endrule

	Reg#(Bool) heartbeat <- mkReg(False);
	rule tick; heartbeat <= !heartbeat; endrule

endmodule
