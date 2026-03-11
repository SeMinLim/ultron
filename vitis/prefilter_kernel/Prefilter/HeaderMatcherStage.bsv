package HeaderMatcherStage;

import Vector::*;

import PrefilterTypes::*;

interface HeaderMatcherStageIfc;
  method Action loadPortGroup(Bit#(PrefilterSlotIdxW) groupId, HmPortGroup group);
  method Action loadRuleBinding(Bit#(PrefilterSlotIdxW) slot, Bit#(32) ruleId, Bit#(PrefilterSlotIdxW) groupId, HmDirection direction);
  method PrefilterRuleMask filter(PrefilterRuleMask candidates, Bit#(16) srcPort, Bit#(16) dstPort);
  method Bit#(32) firstRuleIdFromMask(PrefilterRuleMask mask);
endinterface

module mkHeaderMatcherStage(HeaderMatcherStageIfc);
  Vector#(PrefilterRuleSlots, Reg#(HmPortGroup)) groups <- replicateM(mkReg(wildcardGroup()));
  Vector#(PrefilterRuleSlots, Reg#(Bool)) groupValid <- replicateM(mkReg(False));

  Vector#(PrefilterRuleSlots, Reg#(Bit#(32))) slotRuleId <- replicateM(mkReg(0));
  Vector#(PrefilterRuleSlots, Reg#(Bit#(PrefilterSlotIdxW))) slotGroupId <- replicateM(mkReg(0));
  Vector#(PrefilterRuleSlots, Reg#(Bool)) slotValid <- replicateM(mkReg(False));

  method Action loadPortGroup(Bit#(PrefilterSlotIdxW) groupId, HmPortGroup group);
    groups[groupId] <= group;
    groupValid[groupId] <= True;
  endmethod

  method Action loadRuleBinding(Bit#(PrefilterSlotIdxW) slot, Bit#(32) ruleId, Bit#(PrefilterSlotIdxW) groupId, HmDirection direction);
    let _ = direction;
    slotRuleId[slot] <= ruleId;
    slotGroupId[slot] <= groupId;
    slotValid[slot] <= True;
  endmethod

  method PrefilterRuleMask filter(PrefilterRuleMask candidates, Bit#(16) srcPort, Bit#(16) dstPort);
    PrefilterRuleMask filtered = 0;

    for (Integer slot = 0; slot < valueOf(PrefilterRuleSlots); slot = slot + 1) begin
      if (candidates[slot] == 1'b1 && slotValid[slot]) begin
        Bit#(PrefilterSlotIdxW) groupId = slotGroupId[slot];
        if (groupValid[groupId]) begin
          HmPortGroup group = groups[groupId];
          Bool matchSrc = portInGroup(group, srcPort);
          Bool matchDst = portInGroup(group, dstPort);
          if (matchSrc || matchDst) begin
            filtered = filtered | (64'h1 << fromInteger(slot));
          end
        end
      end
    end

    return filtered;
  endmethod

  method Bit#(32) firstRuleIdFromMask(PrefilterRuleMask mask);
    Bit#(32) firstId = 0;
    Bool found = False;
    for (Integer slot = 0; slot < valueOf(PrefilterRuleSlots); slot = slot + 1) begin
      if (!found && mask[slot] == 1'b1 && slotValid[slot]) begin
        firstId = slotRuleId[slot];
        found = True;
      end
    end
    return firstId;
  endmethod
endmodule

endpackage: HeaderMatcherStage
