import FIFO::*;
import FIFOF::*;
import Vector::*;

import Parser::*;
import ParserTypes::*;
import PrefilterPipeline::*;
import PrefilterTypes::*;
import RuleLoader::*;
import shift_or::*;

typedef 2 MemPortCnt;

typedef struct {
  Bit#(64) addr;
  Bit#(32) bytes;
} MemPortReq deriving (Eq, Bits);

interface MemPortIfc;
  method ActionValue#(MemPortReq) readReq;
  method ActionValue#(MemPortReq) writeReq;
  method ActionValue#(Bit#(512)) writeWord;
  method Action readWord(Bit#(512) word);
endinterface

interface KernelMainIfc;
  method Action start(Bit#(32) param);
  method ActionValue#(Bool) done;
  interface Vector#(MemPortCnt, MemPortIfc) mem;
endinterface

module mkKernelMain(KernelMainIfc);
  FIFO#(Bit#(32)) startQ <- mkFIFO;
  FIFO#(Bool) doneQ <- mkFIFO;

  Vector#(MemPortCnt, FIFO#(MemPortReq)) readReqQs <- replicateM(mkFIFO);
  Vector#(MemPortCnt, FIFO#(MemPortReq)) writeReqQs <- replicateM(mkFIFO);
  Vector#(MemPortCnt, FIFO#(Bit#(512))) writeWordQs <- replicateM(mkFIFO);
  Vector#(MemPortCnt, FIFO#(Bit#(512))) readWordQs <- replicateM(mkFIFO);

  ParserIfc parser <- mkParser;
  PrefilterPipelineIfc prefilter <- mkPrefilterPipeline;
  RuleLoaderIfc ruleLoader <- mkRuleLoader;

  Reg#(Bool) started <- mkReg(False);
  Reg#(Bool) reqIssued <- mkReg(False);
  Reg#(Bit#(64)) baseAddr <- mkReg(0);
  Reg#(Bit#(32)) opCmd <- mkReg(0);

  Reg#(Bit#(32)) loadCnt <- mkReg(0);
  Reg#(Bit#(32)) matchCnt <- mkReg(0);
  Reg#(Bit#(32)) patternHitCnt <- mkReg(0);
  Reg#(Bit#(32)) cycleCounter <- mkReg(0);
  Reg#(Bit#(32)) commandStartCycle <- mkReg(0);
  Reg#(Bit#(32)) requestIssuedCycle <- mkReg(0);
  Reg#(Bool) parserActive <- mkReg(False);
  Reg#(Bit#(32)) parserStartCycle <- mkReg(0);

  rule incrementCycleCounter;
    cycleCounter <= cycleCounter + 1;
  endrule

  rule systemStart(!started);
    startQ.deq;
    opCmd <= startQ.first;
    started <= True;
    reqIssued <= False;
    baseAddr <= 0;
    commandStartCycle <= cycleCounter;
    requestIssuedCycle <= cycleCounter;
    parserActive <= False;
  endrule

  rule issueReq(started && !reqIssued);
    readReqQs[0].enq(MemPortReq { addr: baseAddr, bytes: 64 });
    writeReqQs[1].enq(MemPortReq { addr: baseAddr, bytes: 64 });
    reqIssued <= True;
    requestIssuedCycle <= cycleCounter;
  endrule

  rule consumeRead(started && reqIssued && !parserActive);
    readWordQs[0].deq;
    let incomingWord = readWordQs[0].first;
    let decodedFields = ruleLoader.parseWord(incomingWord);
    Bit#(64) payload64 = decodedFields.payload64;
    Bit#(64) rule64 = decodedFields.rule64;

    Bool isMatchCmd = opCmd[0] == 1;
    Bool hit = False;
    Bit#(32) nextLoadCount = loadCnt;
    Bit#(32) nextMatchCount = matchCnt;
    Bit#(32) nextPatternHitCount = patternHitCnt;

    if (isMatchCmd) begin
      parser.parse(incomingWord);
      parserActive <= True;
      parserStartCycle <= cycleCounter;
    end else begin
      Bit#(PrefilterSlotIdxW) slot = truncate(decodedFields.portGroupId);
      Bit#(8) patternLen = decodedFields.patternLen;
      Bit#(32) resolvedRuleId = decodedFields.ruleId;
      Bit#(PrefilterSlotIdxW) groupId = truncate(decodedFields.portGroupId);
      Bool slotInRange = decodedFields.portGroupId < fromInteger(valueOf(PrefilterRuleSlots));
      Bool ruleLoadOk = (patternLen >= 1 && patternLen <= 8) && slotInRange;

      HmPortGroupType groupType = HmPortGroupWildcard;
      if (decodedFields.portGroupType == 2'b01) begin
        groupType = HmPortGroupSingle;
      end else if (decodedFields.portGroupType == 2'b10) begin
        groupType = HmPortGroupRange;
      end else if (decodedFields.portGroupType == 2'b11) begin
        groupType = HmPortGroupList;
      end

      Vector#(HmMaxPortsPerGroup, Bit#(16)) listPorts = replicate(0);
      listPorts[0] = decodedFields.groupPortSingle;
      Bit#(4) listCount = (groupType == HmPortGroupList) ? 1 : 0;

      HmPortGroup groupCfg = HmPortGroup {
        groupType: groupType,
        singlePort: decodedFields.groupPortSingle,
        rangeStart: decodedFields.groupRangeStart,
        rangeEnd: decodedFields.groupRangeEnd,
        listPorts: listPorts,
        listCount: listCount
      };

      HmDirection dir = HmDirectionAny;
      if (decodedFields.portDirection == 2'b00) dir = HmDirectionRequest;
      else if (decodedFields.portDirection == 2'b01) dir = HmDirectionResponse;

      if (ruleLoadOk) begin
        prefilter.loadRule(slot,
                           rule64,
                           patternLen,
                           resolvedRuleId,
                           decodedFields.ruleProto,
                           groupId,
                           groupCfg,
                           dir,
                           decodedFields.nfFingerprint);
      end

      if (decodedFields.nfEnable) begin
        prefilter.setNfpsmEnabled(True);
      end

      Bit#(3) loadBucketIndex = shiftOrBucketIndex(rule64);
      Bit#(8) loadBucketBitmap = prefilter.fpsmBucketBitmap;

      nextLoadCount = loadCnt + 1;
      loadCnt <= nextLoadCount;
      matchCnt <= nextMatchCount;
      patternHitCnt <= nextPatternHitCount;
      Bit#(512) outgoingWord = 0;
      outgoingWord[31:0] = nextLoadCount;
      outgoingWord[63:32] = nextMatchCount;
      outgoingWord[95:64] = nextPatternHitCount;
      outgoingWord[159:96] = payload64;
      outgoingWord[191:160] = resolvedRuleId;
      outgoingWord[223:192] = 0;
      outgoingWord[224] = pack(hit);
      outgoingWord[225] = pack(isMatchCmd);
      outgoingWord[287:256] = cycleCounter - commandStartCycle;
      outgoingWord[319:288] = cycleCounter - requestIssuedCycle;
      outgoingWord[351:320] = requestIssuedCycle - commandStartCycle;
      outgoingWord[383:352] = 1;
      outgoingWord[415:384] = 0;
      outgoingWord[416] = 0;
      outgoingWord[417] = 0;
      outgoingWord[425:418] = 0;
      outgoingWord[441:426] = 0;
      outgoingWord[457:442] = 0;
      outgoingWord[480] = 0;
      outgoingWord[483:481] = loadBucketIndex;
      outgoingWord[491:484] = loadBucketBitmap;
      outgoingWord[492] = 0;
      outgoingWord[493] = 0;
      outgoingWord[494] = pack(ruleLoadOk);
      outgoingWord[510:495] = 0;
      outgoingWord[511] = pack(decodedFields.nfEnable);
      writeWordQs[1].enq(outgoingWord);
      reqIssued <= False;
      started <= False;
      doneQ.enq(True);
    end
  endrule

  rule finishMatchCommand(parserActive && parser.metaValid);
    let meta = parser.metaFirst;
    parser.metaDeq;

    let stage = prefilter.runMatch(meta.payloadWindow, meta.srcPort, meta.dstPort, meta.protocol);
    Bit#(3) filterBucketIndex = shiftOrBucketIndex(meta.payload64);
    Bit#(8) filterBucketBitmap = stage.bucketBitmap;
    Bool fpsmHit = meta.supported && stage.fpsmHit;
    Bool headerHit = meta.supported && stage.headerHit;
    Bool nfpsmHit = meta.supported && stage.nfpsmHit;
    Bool hit = meta.supported && stage.finalHit;

    Bit#(32) nextMatchCount = matchCnt + 1;
    Bit#(32) nextPatternHitCount = patternHitCnt + (hit ? 1 : 0);

    matchCnt <= nextMatchCount;
    patternHitCnt <= nextPatternHitCount;

    Bit#(512) outgoingWord = 0;
    outgoingWord[31:0] = loadCnt;
    outgoingWord[63:32] = nextMatchCount;
    outgoingWord[95:64] = nextPatternHitCount;
    outgoingWord[159:96] = meta.payload64;
    outgoingWord[191:160] = stage.firstRuleId;
    outgoingWord[207:192] = meta.srcPort;
    outgoingWord[223:208] = meta.dstPort;
    outgoingWord[224] = pack(hit);
    outgoingWord[225] = 1;
    outgoingWord[287:256] = cycleCounter - commandStartCycle;
    outgoingWord[319:288] = cycleCounter - requestIssuedCycle;
    outgoingWord[351:320] = requestIssuedCycle - commandStartCycle;
    outgoingWord[383:352] = 1;
    outgoingWord[415:384] = cycleCounter - parserStartCycle;
    outgoingWord[416] = pack(meta.valid);
    outgoingWord[417] = pack(meta.supported);
    outgoingWord[425:418] = meta.protocol;
    outgoingWord[441:426] = meta.payloadOffset;
    outgoingWord[457:442] = meta.payloadLength;
    outgoingWord[480] = pack(fpsmHit);
    outgoingWord[483:481] = filterBucketIndex;
    outgoingWord[491:484] = filterBucketBitmap;
    outgoingWord[492] = pack(headerHit);
    outgoingWord[493] = pack(nfpsmHit);
    outgoingWord[494] = pack(hit);
    outgoingWord[510:495] = stage.packetFingerprint;
    outgoingWord[511] = pack(meta.supported);
    writeWordQs[1].enq(outgoingWord);

    parserActive <= False;
    reqIssued <= False;
    started <= False;
    doneQ.enq(True);
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

  method Action start(Bit#(32) param) if (!started);
    startQ.enq(param);
  endmethod

  method ActionValue#(Bool) done;
    doneQ.deq;
    return doneQ.first;
  endmethod

  interface mem = mem_;
endmodule
