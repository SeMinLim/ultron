package HeaderMatcherStage;

import Vector::*;

import PrefilterTypes::*;

interface HeaderMatcherStageIfc;
  method Action loadPortGroup(Bit#(6) groupId, HmPortGroup group);
  method Action loadRuleBinding(Bit#(6) slot, Bit#(32) ruleId, Bit#(6) groupId, HmDirection direction);
  method Bit#(64) filter(Bit#(64) candidates, Bit#(16) srcPort, Bit#(16) dstPort);
  method Bit#(32) ruleIdForSlot(Bit#(6) slot);
endinterface

module mkHeaderMatcherStage(HeaderMatcherStageIfc);
  Vector#(64, Reg#(HmPortGroup)) groups <- replicateM(mkReg(wildcardGroup()));
  Vector#(64, Reg#(Bool)) groupValid <- replicateM(mkReg(False));

  Vector#(64, Reg#(Bit#(32))) slotRuleId <- replicateM(mkReg(0));
  Vector#(64, Reg#(Bit#(6))) slotGroupId <- replicateM(mkReg(0));
  Vector#(64, Reg#(HmDirection)) slotDirection <- replicateM(mkReg(HmDirectionAny));
  Vector#(64, Reg#(Bool)) slotValid <- replicateM(mkReg(False));

  method Action loadPortGroup(Bit#(6) groupId, HmPortGroup group);
    groups[groupId] <= group;
    groupValid[groupId] <= True;
  endmethod

  method Action loadRuleBinding(Bit#(6) slot, Bit#(32) ruleId, Bit#(6) groupId, HmDirection direction);
    slotRuleId[slot] <= ruleId;
    slotGroupId[slot] <= groupId;
    slotDirection[slot] <= direction;
    slotValid[slot] <= True;
  endmethod

  method Bit#(64) filter(Bit#(64) candidates, Bit#(16) srcPort, Bit#(16) dstPort);
    Bit#(64) filtered = 0;

    for (Integer slot = 0; slot < 16; slot = slot + 1) begin
      if (candidates[slot] == 1'b1 && slotValid[slot]) begin
        Bit#(6) groupId = slotGroupId[slot];
        Bool validGroup = groupValid[groupId] || (groupId == 0);
        HmPortGroup group = groups[groupId];
        if (!validGroup) begin
          group = wildcardGroup();
        end

        Bool matchSrc = portInGroup(group, srcPort);
        Bool matchDst = portInGroup(group, dstPort);
        Bool portOk = case (slotDirection[slot])
          HmDirectionRequest: matchDst;
          HmDirectionResponse: matchSrc;
          HmDirectionAny: matchSrc || matchDst;
        endcase;
        if (portOk) begin
          filtered = filtered | (64'h1 << slot);
        end
      end
    end

    return filtered;
  endmethod

  method Bit#(32) ruleIdForSlot(Bit#(6) slot);
    return slotRuleId[slot];
  endmethod
endmodule

endpackage: HeaderMatcherStage
