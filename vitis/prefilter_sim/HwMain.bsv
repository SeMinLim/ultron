import FIFO::*;
import FIFOF::*;
import Clocks::*;
import Vector::*;
import BRAM::*;
import BRAMFIFO::*;

import PcieCtrl::*;
import PacketParser::*;
import PacketParserTypes::*;
import FPSM::*;
import RuleReduction::*;
import TrafficManager::*;

interface HwMainIfc;
endinterface

module mkHwMain#(PcieUserIfc pcie) 
	(HwMainIfc);

	Clock curClk <- exposeCurrentClock;
	Reset curRst <- exposeCurrentReset;

	Clock pcieclk = pcie.user_clk;
	Reset pcierst = pcie.user_rst;

	FIFO#(DMAWord) inputQ <- mkSizedBRAMFIFO(512); // 8KBs
	FIFO#(DMAWord) outputQ <- mkSizedBRAMFIFO(512); // 8KBs
	Reg#(Bit#(16)) outputCntUp <- mkReg(0);
	Reg#(Bit#(16)) outputCntDn <- mkReg(0);

	Vector#(8, PacketParserIfc) pes <- replicateM(mkPacketParser);
	Vector#(8, Reg#(PacketMeta)) lastMeta <- replicateM(mkRegU);
	Vector#(8, Reg#(Bit#(32))) metaCount <- replicateM(mkReg(0));
	
	// Track byte offset for payload extraction per parser
	Vector#(8, Reg#(Bit#(16))) currentByteOffset <- replicateM(mkReg(0));
	Vector#(8, Reg#(Bool)) metaReady <- replicateM(mkReg(False));
	
	// FPSM instance for pattern matching
	SimpleFPSMIfc fpsm <- mkSimpleFPSM;
	
	// Store FPSM match results (256 bits for 32 lanes × 8 bytes)
	Reg#(Bit#(256)) fpsmMatchResult <- mkReg(0);
	Reg#(Bit#(32)) fpsmMatchCount <- mkReg(0);  // Chunks with at least one match
	Reg#(Bit#(32)) fpsmTotalMatches <- mkReg(0);  // Total individual matches (before reduction)
	
	// Pigasus pipeline stages
	Reg#(Bit#(32)) reducedMatchCount <- mkReg(0);  // Total matches after capping at 8 per chunk
	Reg#(Bit#(32)) headerMatchCount <- mkReg(0);
	Reg#(Bit#(32)) packetCount <- mkReg(0);
	Reg#(Bit#(32)) cleanPacketCount <- mkReg(0);
	Reg#(Bit#(32)) nfpsmPacketCount <- mkReg(0);
	
	TrafficManagerIfc trafficMgr <- mkTrafficManager;
	
	// Pattern loading state
	Reg#(UInt#(6)) patternLoadLane <- mkReg(0);
	Reg#(Bit#(256)) patternLoadData <- mkReg(0);
	Reg#(Bit#(8)) patternLoadLen <- mkReg(0);
	Reg#(Bit#(16)) patternLoadRuleId <- mkReg(0);
	Reg#(Bit#(3)) patternLoadStage <- mkReg(0);  // 0-7 for loading 8 × 32-bit words
	
	// Buffer for accumulating 256 bits (2 × 128-bit DMAWords)
	Reg#(Maybe#(Bit#(128))) fpsmBuf <- mkReg(tagged Invalid);
	
	// Process FPSM matches through pipeline
	function Action processPipelineMatches(Vector#(OutputSize, Bool) fpsmMatches);
		action
			packetCount <= packetCount + 1;
			
			// Count total matches before reduction
			Bit#(32) totalCount = countMatches(fpsmMatches);
			fpsmTotalMatches <= fpsmTotalMatches + totalCount;
			
			// RULE REDUCTION: Cap at 8 matches
			Bit#(32) reducedCount = reduceMatchCount(fpsmMatches);
			reducedMatchCount <= reducedMatchCount + reducedCount;
			
			// HEADER MATCHING: Simulate checking packet headers
			// In real implementation, would use RuleTable and PortGroup
			// For now, simulate 50% pass rate
			Bit#(32) headerMatched = reducedCount >> 1;
			headerMatchCount <= headerMatchCount + headerMatched;
			
			// Build simulated header match results
			Vector#(8, HeaderMatchResult) headerResults = replicate(
				HeaderMatchResult {
					valid: False,
					laneIdx: 0,
					matchLen: 0,
					ruleId: 0
				}
			);
			
			for (Integer i = 0; i < 4; i = i + 1) begin
				if (fromInteger(i) < headerMatched) begin
					headerResults[i] = HeaderMatchResult {
						valid: True,
						laneIdx: fromInteger(i),
						matchLen: 4,
						ruleId: fromInteger(100 + i)
					};
				end
			end
			
			// TRAFFIC MANAGER: Decide clean vs. NFPSM
			trafficMgr.putHeaderResults(headerResults);
		endaction
	endfunction

	Reg#(Bit#(3)) inPe <- mkReg(0);
	Reg#(Bit#(16)) inWordsLeft <- mkReg(0);
	Reg#(Bit#(3)) outPe <- mkReg(0);
	Reg#(Bit#(3)) dispatchBufCount <- mkReg(0);
	Reg#(Bit#(3)) dispatchBufOutIdx <- mkReg(4);
	Vector#(4, Reg#(DMAWord)) dispatchBuf <- replicateM(mkRegU);

	rule dispatchBuffer(inWordsLeft == 0 && dispatchBufCount < 4 && dispatchBufOutIdx == 4);
		inputQ.deq;
		dispatchBuf[dispatchBufCount] <= inputQ.first;
		dispatchBufCount <= dispatchBufCount + 1;
	endrule

	rule dispatchNewPacket(inWordsLeft == 0 && dispatchBufCount == 4 && dispatchBufOutIdx == 4);
		Bit#(16) totalLength = dispatchBuf[1][127:112];
		Bit#(32) frameLength = 14 + zeroExtend(totalLength);
		Bit#(32) totalWords32 = (frameLength + 15) >> 4;
		Bit#(16) totalWords = truncate(totalWords32);

		dispatchBufCount <= 0;
		dispatchBufOutIdx <= 0;
		if (totalWords <= 4) begin
			inWordsLeft <= 0;
			inPe <= inPe + 1;
		end else begin
			inWordsLeft <= totalWords - 4;
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

		if (pes[idx0].payloadValid && metaReady[idx0]) begin
			DMAWord payload = pes[idx0].payloadFirst;
			outputQ.enq(payload);
			pes[idx0].payloadDeq;
			outPe <= idx0 + 1;
			outputCntUp <= outputCntUp + 1;
			
			// Track byte offset and determine if this word is in payload region
			Bit#(16) byteStart = currentByteOffset[idx0];
			Bit#(16) byteEnd = byteStart + 16; // DMAWord is 128 bits = 16 bytes
			Bit#(16) payloadStart = lastMeta[idx0].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx0].payloadLength;
			
			// Only send to FPSM if word starts at or after payload offset
			// This avoids header bytes contaminating the pattern match
			// Note: This means we skip partial words at the header/payload boundary
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				// Buffer two 128-bit words to make 256 bits for FPSM
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			// Update byte offset
			currentByteOffset[idx0] <= byteEnd;
			
			// Reset at packet end (when we've processed all payload)
			if (byteEnd >= payloadEnd) begin
				metaReady[idx0] <= False;
			end
		end else if (pes[idx1].payloadValid && metaReady[idx1]) begin
			DMAWord payload = pes[idx1].payloadFirst;
			outputQ.enq(payload);
			pes[idx1].payloadDeq;
			outPe <= idx1 + 1;
			outputCntUp <= outputCntUp + 1;
			
			Bit#(16) byteStart = currentByteOffset[idx1];
			Bit#(16) byteEnd = byteStart + 16;
			Bit#(16) payloadStart = lastMeta[idx1].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx1].payloadLength;
			
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			currentByteOffset[idx1] <= byteEnd;
			
			if (byteEnd >= payloadEnd) begin
				metaReady[idx1] <= False;
			end
		end else if (pes[idx2].payloadValid && metaReady[idx2]) begin
			DMAWord payload = pes[idx2].payloadFirst;
			outputQ.enq(payload);
			pes[idx2].payloadDeq;
			outPe <= idx2 + 1;
			outputCntUp <= outputCntUp + 1;
			
			Bit#(16) byteStart = currentByteOffset[idx2];
			Bit#(16) byteEnd = byteStart + 16;
			Bit#(16) payloadStart = lastMeta[idx2].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx2].payloadLength;
			
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			currentByteOffset[idx2] <= byteEnd;
			
			if (byteEnd >= payloadEnd) begin
				metaReady[idx2] <= False;
			end
		end else if (pes[idx3].payloadValid && metaReady[idx3]) begin
			DMAWord payload = pes[idx3].payloadFirst;
			outputQ.enq(payload);
			pes[idx3].payloadDeq;
			outPe <= idx3 + 1;
			outputCntUp <= outputCntUp + 1;
			
			Bit#(16) byteStart = currentByteOffset[idx3];
			Bit#(16) byteEnd = byteStart + 16;
			Bit#(16) payloadStart = lastMeta[idx3].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx3].payloadLength;
			
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			currentByteOffset[idx3] <= byteEnd;
			
			if (byteEnd >= payloadEnd) begin
				metaReady[idx3] <= False;
			end
		end else if (pes[idx4].payloadValid && metaReady[idx4]) begin
			DMAWord payload = pes[idx4].payloadFirst;
			outputQ.enq(payload);
			pes[idx4].payloadDeq;
			outPe <= idx4 + 1;
			outputCntUp <= outputCntUp + 1;
			
			Bit#(16) byteStart = currentByteOffset[idx4];
			Bit#(16) byteEnd = byteStart + 16;
			Bit#(16) payloadStart = lastMeta[idx4].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx4].payloadLength;
			
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			currentByteOffset[idx4] <= byteEnd;
			
			if (byteEnd >= payloadEnd) begin
				metaReady[idx4] <= False;
			end
		end else if (pes[idx5].payloadValid && metaReady[idx5]) begin
			DMAWord payload = pes[idx5].payloadFirst;
			outputQ.enq(payload);
			pes[idx5].payloadDeq;
			outPe <= idx5 + 1;
			outputCntUp <= outputCntUp + 1;
			
			Bit#(16) byteStart = currentByteOffset[idx5];
			Bit#(16) byteEnd = byteStart + 16;
			Bit#(16) payloadStart = lastMeta[idx5].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx5].payloadLength;
			
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			currentByteOffset[idx5] <= byteEnd;
			
			if (byteEnd >= payloadEnd) begin
				metaReady[idx5] <= False;
			end
		end else if (pes[idx6].payloadValid && metaReady[idx6]) begin
			DMAWord payload = pes[idx6].payloadFirst;
			outputQ.enq(payload);
			pes[idx6].payloadDeq;
			outPe <= idx6 + 1;
			outputCntUp <= outputCntUp + 1;
			
			Bit#(16) byteStart = currentByteOffset[idx6];
			Bit#(16) byteEnd = byteStart + 16;
			Bit#(16) payloadStart = lastMeta[idx6].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx6].payloadLength;
			
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			currentByteOffset[idx6] <= byteEnd;
			
			if (byteEnd >= payloadEnd) begin
				metaReady[idx6] <= False;
			end
		end else if (pes[idx7].payloadValid && metaReady[idx7]) begin
			DMAWord payload = pes[idx7].payloadFirst;
			outputQ.enq(payload);
			pes[idx7].payloadDeq;
			outPe <= idx7 + 1;
			outputCntUp <= outputCntUp + 1;
			
			Bit#(16) byteStart = currentByteOffset[idx7];
			Bit#(16) byteEnd = byteStart + 16;
			Bit#(16) payloadStart = lastMeta[idx7].payloadOffset;
			Bit#(16) payloadEnd = payloadStart + lastMeta[idx7].payloadLength;
			
			Bool inPayload = (byteEnd > payloadStart) && (byteStart < payloadEnd);
			
			if (inPayload) begin
				if (fpsmBuf matches tagged Invalid) begin
					fpsmBuf <= tagged Valid payload;
				end else begin
					Bit#(256) fpsmInput = {payload, fromMaybe(0, fpsmBuf)};
					Vector#(OutputSize, Bool) fpsmMatches = fpsm.process(fpsmInput);
					Bit#(256) matchBits = 0;
					for (Integer i = 0; i < valueOf(OutputSize); i = i + 1) begin
						matchBits[i] = pack(fpsmMatches[i]);
					end
					if (matchBits != 0) begin
						fpsmMatchResult <= matchBits;
						fpsmMatchCount <= fpsmMatchCount + 1;
						// Process through Pigasus pipeline
						processPipelineMatches(fpsmMatches);
					end
					fpsmBuf <= tagged Invalid;
				end
			end
			
			currentByteOffset[idx7] <= byteEnd;
			
			if (byteEnd >= payloadEnd) begin
				metaReady[idx7] <= False;
			end
		end
	endrule
	
	// Drain Traffic Manager decisions
	rule drainTrafficDecision;
		let decision <- trafficMgr.getDecision();
		if (decision.needsNFPSM) begin
			nfpsmPacketCount <= nfpsmPacketCount + 1;
		end else begin
			cleanPacketCount <= cleanPacketCount + 1;
		end
	endrule

	rule drainMeta0(pes[0].metaValid);
		let m = pes[0].metaFirst;
		pes[0].metaDeq;
		lastMeta[0] <= m;
		metaCount[0] <= metaCount[0] + 1;
		currentByteOffset[0] <= 0;
		metaReady[0] <= True;
	endrule
	rule drainMeta1(pes[1].metaValid);
		let m = pes[1].metaFirst;
		pes[1].metaDeq;
		lastMeta[1] <= m;
		metaCount[1] <= metaCount[1] + 1;
		currentByteOffset[1] <= 0;
		metaReady[1] <= True;
	endrule
	rule drainMeta2(pes[2].metaValid);
		let m = pes[2].metaFirst;
		pes[2].metaDeq;
		lastMeta[2] <= m;
		metaCount[2] <= metaCount[2] + 1;
		currentByteOffset[2] <= 0;
		metaReady[2] <= True;
	endrule
	rule drainMeta3(pes[3].metaValid);
		let m = pes[3].metaFirst;
		pes[3].metaDeq;
		lastMeta[3] <= m;
		metaCount[3] <= metaCount[3] + 1;
		currentByteOffset[3] <= 0;
		metaReady[3] <= True;
	endrule
	rule drainMeta4(pes[4].metaValid);
		let m = pes[4].metaFirst;
		pes[4].metaDeq;
		lastMeta[4] <= m;
		metaCount[4] <= metaCount[4] + 1;
		currentByteOffset[4] <= 0;
		metaReady[4] <= True;
	endrule
	rule drainMeta5(pes[5].metaValid);
		let m = pes[5].metaFirst;
		pes[5].metaDeq;
		lastMeta[5] <= m;
		metaCount[5] <= metaCount[5] + 1;
		currentByteOffset[5] <= 0;
		metaReady[5] <= True;
	endrule
	rule drainMeta6(pes[6].metaValid);
		let m = pes[6].metaFirst;
		pes[6].metaDeq;
		lastMeta[6] <= m;
		metaCount[6] <= metaCount[6] + 1;
		currentByteOffset[6] <= 0;
		metaReady[6] <= True;
	endrule
	rule drainMeta7(pes[7].metaValid);
		let m = pes[7].metaFirst;
		pes[7].metaDeq;
		lastMeta[7] <= m;
		metaCount[7] <= metaCount[7] + 1;
		currentByteOffset[7] <= 0;
		metaReady[7] <= True;
	endrule

	BRAM2Port#(Bit#(6),DMAWord) page <- mkBRAM2Server(defaultValue); // tag, total words,words recv

	FIFO#(Bit#(8)) streamReadQ <- mkSizedBRAMFIFO(1024); // streamid, page offset
	FIFO#(Bit#(8)) streamWriteQ <- mkSizedBRAMFIFO(1024); // streamid, page offset

	Reg#(Bit#(32)) streamReadCnt <- mkReg(0);
	Reg#(Bit#(32)) streamWriteCnt <- mkReg(0);
	rule getCmd;
		let w <- pcie.dataReceive;
		let a = w.addr;
		let d = w.data;
		// PCIe IO is done at 4 byte granularities
		// lower 2 bits are always zero
		let off = (a>>2);
		// off == (in|out)<<8, d == page offset
		if ( off == 0 ) begin
			streamReadQ.enq(truncate(d));
		end else if ( off == 1 ) begin
			streamWriteQ.enq(truncate(d));
		end 
		// Pattern loading registers (offsets 16-31)
		else if ( off == 16 ) begin
			// Set lane index for pattern loading
			patternLoadLane <= unpack(truncate(d));
			patternLoadStage <= 0;
		end else if ( off == 17 ) begin
			// Set pattern length
			patternLoadLen <= truncate(d);
		end else if ( off == 18 ) begin
			// Set rule ID
			patternLoadRuleId <= truncate(d);
		end else if ( off == 19 ) begin
			Bit#(256) newData = patternLoadData;
			newData[31:0] = d;
			patternLoadData <= newData;
		end else if ( off == 20 ) begin
			Bit#(256) newData = patternLoadData;
			newData[63:32] = d;
			patternLoadData <= newData;
		end else if ( off == 21 ) begin
			Bit#(256) newData = patternLoadData;
			newData[95:64] = d;
			patternLoadData <= newData;
		end else if ( off == 22 ) begin
			Bit#(256) newData = patternLoadData;
			newData[127:96] = d;
			patternLoadData <= newData;
		end else if ( off == 23 ) begin
			Bit#(256) newData = patternLoadData;
			newData[159:128] = d;
			patternLoadData <= newData;
		end else if ( off == 24 ) begin
			Bit#(256) newData = patternLoadData;
			newData[191:160] = d;
			patternLoadData <= newData;
		end else if ( off == 25 ) begin
			Bit#(256) newData = patternLoadData;
			newData[223:192] = d;
			patternLoadData <= newData;
		end else if ( off == 26 ) begin
			// Last word - also commit the pattern
			Bit#(256) newData = patternLoadData;
			newData[255:224] = d;
			patternLoadData <= newData;
			
			LanePattern pat = LanePattern {
				pattern: newData,
				patternLen: patternLoadLen,
				ruleId: patternLoadRuleId,
				valid: True
			};
			fpsm.setPattern(patternLoadLane, pat);
		end
	endrule

	FIFO#(IOReadReq) reqQ <- mkFIFO;
	rule readStat;
		let r <- pcie.dataReq;
		let a = r.addr;
		// PCIe IO is done at 4 byte granularities
		// lower 2 bits are always zero
		let offset = (a>>2);

		if ( offset == 0 ) begin
			pcie.dataSend(r, streamReadCnt);
		end else if ( offset == 1 ) begin
			pcie.dataSend(r, streamWriteCnt);
		end else if ( offset == 2 ) begin
			// FPSM match result bits [31:0] (lanes 0-3)
			pcie.dataSend(r, truncate(fpsmMatchResult));
		end else if ( offset == 3 ) begin
			// FPSM match result bits [63:32] (lanes 4-7)
			pcie.dataSend(r, truncate(fpsmMatchResult >> 32));
		end else if ( offset == 4 ) begin
			// FPSM match result bits [95:64] (lanes 8-11)
			pcie.dataSend(r, truncate(fpsmMatchResult >> 64));
		end else if ( offset == 5 ) begin
			// FPSM match result bits [127:96] (lanes 12-15)
			pcie.dataSend(r, truncate(fpsmMatchResult >> 96));
		end else if ( offset == 6 ) begin
			// FPSM match result bits [159:128] (lanes 16-19)
			pcie.dataSend(r, truncate(fpsmMatchResult >> 128));
		end else if ( offset == 7 ) begin
			// FPSM match result bits [191:160] (lanes 20-23)
			pcie.dataSend(r, truncate(fpsmMatchResult >> 160));
		end else if ( offset == 8 ) begin
			// FPSM match result bits [223:192] (lanes 24-27)
			pcie.dataSend(r, truncate(fpsmMatchResult >> 192));
		end else if ( offset == 9 ) begin
			// FPSM match result bits [255:224] (lanes 28-31)
			pcie.dataSend(r, truncate(fpsmMatchResult >> 224));
		end else if ( offset == 10 ) begin
			// FPSM chunks with matches (number of 256-bit chunks that had at least one match)
			pcie.dataSend(r, fpsmMatchCount);
		end else if ( offset == 11 ) begin
			// FPSM total individual matches (before reduction)
			pcie.dataSend(r, fpsmTotalMatches);
		end else if ( offset == 12 ) begin
			// Rule-reduced match count (after capping at 8 per chunk)
			pcie.dataSend(r, reducedMatchCount);
		end else if ( offset == 13 ) begin
			// Header-matched count
			pcie.dataSend(r, headerMatchCount);
		end else if ( offset == 14 ) begin
			// Clean packet count
			pcie.dataSend(r, cleanPacketCount);
		end else if ( offset == 15 ) begin
			// NFPSM packet count
			pcie.dataSend(r, nfpsmPacketCount);
		end else if ( offset == 16 ) begin
			// Total FPSM chunks processed
			pcie.dataSend(r, packetCount);
		end else if ( offset >= 17 ) begin
			page.portB.request.put(BRAMRequest{write:False,responseOnWrite:False,address:truncate(offset),datain:?});
			reqQ.enq(r);
		end else begin
			pcie.dataSend(r, 32'hcccccccc);
		end
	endrule
	rule relayPageRead;
		let r <- page.portB.response.get();
		let req = reqQ.first;
		reqQ.deq;
		pcie.dataSend(req,truncate(r));
	endrule

	rule dmaReadReq;
		streamReadQ.deq;
		let poff = streamReadQ.first;
		pcie.dmaReadReq( (zeroExtend(poff)<<10), 64); // offset, words
		streamReadCnt <= streamReadCnt + 1;
	endrule
	Reg#(Bit#(32)) dmaReadWords <- mkReg(0);
	rule dmaReadDatal;
		DMAWord rd <- pcie.dmaReadWord;
		page.portA.request.put(BRAMRequest{write:True,responseOnWrite:False,address:truncate(dmaReadWords),datain:rd});
		dmaReadWords <= dmaReadWords + 1;
		
		inputQ.enq(rd);
	endrule

	Reg#(Bit#(16)) curOutLeftUp <- mkReg(0);
	Reg#(Bit#(16)) curOutLeftDn <- mkReg(0);
	rule dmaWriteReq (outputCntUp - outputCntDn >= 64 && curOutLeftUp-curOutLeftDn < 128);
		streamWriteQ.deq;
		let woff = streamWriteQ.first;
		pcie.dmaWriteReq((zeroExtend(woff)<<10), 64);

		curOutLeftUp <= curOutLeftUp + 64;
		outputCntDn <= outputCntDn + 64;
		streamWriteCnt <= streamWriteCnt + 1;
	endrule
	rule dmaWriteData(curOutLeftUp != curOutLeftDn);
		curOutLeftDn <= curOutLeftDn + 1;
		outputQ.deq;
		pcie.dmaWriteData(outputQ.first);
	endrule
endmodule
