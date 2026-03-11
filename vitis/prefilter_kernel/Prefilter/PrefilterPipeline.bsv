package PrefilterPipeline;

import PrefilterTypes::*;
import FpsmStage::*;
import HeaderMatcherStage::*;
import NfpsmStage::*;
import RuleReductionStage::*;

interface PrefilterPipelineIfc;
  method Action loadRule(Bit#(PrefilterSlotIdxW) slot,
                         Bit#(64) pattern,
                         Bit#(8) patternLen,
                         Bit#(32) ruleId,
                         Bit#(8) ruleProto,
                         Bit#(PrefilterSlotIdxW) portGroupId,
                         HmPortGroup portGroup,
                         HmDirection direction,
                         Bit#(16) nfFingerprint);
  method Action setNfpsmEnabled(Bool enabled);
  method PrefilterMatchResult runMatch(PrefilterPayloadWindow payloadWindow, Bit#(16) srcPort, Bit#(16) dstPort, Bit#(8) proto);
  method Bit#(8) fpsmBucketBitmap;
endinterface

module mkPrefilterPipeline(PrefilterPipelineIfc);
  FpsmStageIfc fpsm <- mkFpsmStage;
  HeaderMatcherStageIfc header <- mkHeaderMatcherStage;
  NfpsmStageIfc nfpsm <- mkNfpsmStage;
  RuleReductionStageIfc reducer <- mkRuleReductionStage;

  method Action loadRule(Bit#(PrefilterSlotIdxW) slot,
                         Bit#(64) pattern,
                         Bit#(8) patternLen,
                         Bit#(32) ruleId,
                         Bit#(8) ruleProto,
                         Bit#(PrefilterSlotIdxW) portGroupId,
                         HmPortGroup portGroup,
                         HmDirection direction,
                         Bit#(16) nfFingerprint);
    fpsm.loadRule(slot, pattern, patternLen);
    header.loadPortGroup(portGroupId, portGroup);
    header.loadRuleBinding(slot, ruleId, portGroupId, direction, ruleProto);
    nfpsm.loadRule(slot, pattern, patternLen, nfFingerprint);
  endmethod

  method Action setNfpsmEnabled(Bool enabled);
    nfpsm.setEnabled(enabled);
  endmethod

  method PrefilterMatchResult runMatch(PrefilterPayloadWindow payloadWindow, Bit#(16) srcPort, Bit#(16) dstPort, Bit#(8) proto);
    PrefilterRuleMask fpsmMaskRaw = fpsm.runMatch(payloadWindow);
    PrefilterRuleMask fpsmMask = reducer.reduce64to8(fpsmMaskRaw);

    PrefilterRuleMask headerMask = header.filter(fpsmMask, srcPort, dstPort, proto);

    PrefilterRuleMask nfpsmMaskRaw = nfpsm.filter(headerMask, payloadWindow);
    PrefilterRuleMask finalMask = reducer.reduce8to2(nfpsmMaskRaw);

    Bit#(16) packetFp = 0;
    Bit#(8) buckets = fpsm.bucketBitmap;

    Bool fpsmHit = (fpsmMask != 0);
    Bool headerHit = (headerMask != 0);
    Bool finalHit = (finalMask != 0);
    Bool nfEnabled = nfpsm.enabled;
    Bool nfHit = nfEnabled ? finalHit : headerHit;

    Bit#(32) firstRuleId = header.firstRuleIdFromMask(finalMask);

    return PrefilterMatchResult {
      fpsmHit: fpsmHit,
      headerHit: headerHit,
      nfpsmHit: nfHit,
      finalHit: finalHit,
      firstRuleId: firstRuleId,
      fpsmMask: fpsmMask,
      headerMask: headerMask,
      finalMask: finalMask,
      packetFingerprint: packetFp,
      bucketBitmap: buckets
    };
  endmethod

  method Bit#(8) fpsmBucketBitmap;
    return fpsm.bucketBitmap;
  endmethod
endmodule

endpackage: PrefilterPipeline
