package NfpsmStage;

import Vector::*;

import PrefilterTypes::*;
import PrefilterMatchUtils::*;

interface NfpsmStageIfc;
  method Action setEnabled(Bool enabled);
  method Bool enabled;
  method Action loadRule(Bit#(PrefilterSlotIdxW) slot, Bit#(64) pattern, Bit#(8) patternLen, Bit#(16) fingerprint);
  method PrefilterRuleMask filter(PrefilterRuleMask candidates, PrefilterPayloadWindow payloadWindow);
endinterface

function Bit#(16) defaultFingerprintForPattern(Bit#(64) patternNorm, Bit#(8) patternLen);
  Bit#(4) bitIdx = truncate(fnv1a64(patternNorm, patternLen));
  return 16'h1 << bitIdx;
endfunction

function Vector#(8, Bit#(16)) payloadBucketFingerprints(PrefilterPayloadWindow payloadWindow);
  Vector#(8, Bit#(16)) fpByBucket = replicate(0);

  for (Integer len = 1; len <= 8; len = len + 1) begin
    Bit#(8) lenVal = fromInteger(len);
    Bit#(16) bucketFp = 0;

    for (Integer start = 0; start < valueOf(FpsmParallelWindows); start = start + 1) begin
      Bit#(6) startVal = fromInteger(start);
      Bit#(16) endPos = zeroExtend(startVal) + zeroExtend(lenVal);
      if (endPos <= fromInteger(valueOf(PrefilterPayloadWindowBytes))) begin
        Bit#(64) windowKey = windowKeyByStartLenWide(payloadWindow, startVal, lenVal);
        Bit#(4) bitIdx = truncate(fnv1a64(windowKey, lenVal));
        bucketFp = bucketFp | (16'h1 << bitIdx);
      end
    end

    fpByBucket[len - 1] = bucketFp;
  end

  return fpByBucket;
endfunction

module mkNfpsmStage(NfpsmStageIfc);
  Reg#(Bool) nfEnabled <- mkReg(False);
  Vector#(PrefilterRuleSlots, Reg#(Bit#(3))) ruleBucket <- replicateM(mkReg(0));
  Vector#(PrefilterRuleSlots, Reg#(Bit#(16))) ruleFingerprint <- replicateM(mkReg(0));
  Vector#(PrefilterRuleSlots, Reg#(Bit#(64))) rulePattern <- replicateM(mkReg(0));
  Vector#(PrefilterRuleSlots, Reg#(Bit#(8))) ruleLen <- replicateM(mkReg(0));
  Vector#(PrefilterRuleSlots, Reg#(Bool)) ruleValid <- replicateM(mkReg(False));

  method Action setEnabled(Bool enabled);
    nfEnabled <= enabled;
  endmethod

  method Bool enabled;
    return nfEnabled;
  endmethod

  method Action loadRule(Bit#(PrefilterSlotIdxW) slot, Bit#(64) pattern, Bit#(8) patternLen, Bit#(16) fingerprint);
    if (validPatternLen1to8(patternLen)) begin
      Bit#(3) bucketIdx = bucketForLen1to8(patternLen);
      Bit#(64) patternNorm = normalizePatternByLen(pattern, patternLen);
      Bit#(16) finalFingerprint = (fingerprint != 0) ? fingerprint : defaultFingerprintForPattern(patternNorm, patternLen);

      ruleBucket[slot] <= bucketIdx;
      ruleFingerprint[slot] <= finalFingerprint;
      rulePattern[slot] <= patternNorm;
      ruleLen[slot] <= patternLen;
      ruleValid[slot] <= True;
    end
  endmethod

  method PrefilterRuleMask filter(PrefilterRuleMask candidates, PrefilterPayloadWindow payloadWindow);
    PrefilterRuleMask filtered = candidates;

    if (nfEnabled) begin
      Vector#(8, Bit#(16)) packetFpByBucket = payloadBucketFingerprints(payloadWindow);

      filtered = 0;
      for (Integer slot = 0; slot < valueOf(PrefilterRuleSlots); slot = slot + 1) begin
        if (candidates[slot] == 1'b1 && ruleValid[slot]) begin
          Bit#(3) bucketIdx = ruleBucket[slot];
          Bit#(16) rf = ruleFingerprint[slot];
          Bit#(16) pf = packetFpByBucket[bucketIdx];
          Bool fingerprintOk = ((rf & pf) == rf);

          Bool exactOk = False;
          Bit#(8) lenVal = ruleLen[slot];
          Bit#(64) pat = rulePattern[slot];
          for (Integer start = 0; start < valueOf(FpsmParallelWindows); start = start + 1) begin
            Bit#(6) startVal = fromInteger(start);
            Bit#(16) endPos = zeroExtend(startVal) + zeroExtend(lenVal);
            if (!exactOk && endPos <= fromInteger(valueOf(PrefilterPayloadWindowBytes))) begin
              Bit#(64) windowKey = windowKeyByStartLenWide(payloadWindow, startVal, lenVal);
              if (windowKey == pat) begin
                exactOk = True;
              end
            end
          end

          if (fingerprintOk && exactOk) begin
            filtered = filtered | (64'h1 << fromInteger(slot));
          end
        end
      end
    end

    return filtered;
  endmethod
endmodule

endpackage: NfpsmStage
