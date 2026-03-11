package PrefilterTypes;

import Vector::*;

typedef 64 PrefilterRuleSlots;
typedef 6 PrefilterSlotIdxW;
typedef Bit#(PrefilterRuleSlots) PrefilterRuleMask;

typedef 40 PrefilterPayloadWindowBytes;
typedef 320 PrefilterPayloadWindowW;
typedef Bit#(PrefilterPayloadWindowW) PrefilterPayloadWindow;
typedef 32 FpsmParallelWindows;

typedef enum {
  HmPortGroupWildcard,
  HmPortGroupSingle,
  HmPortGroupRange,
  HmPortGroupList
} HmPortGroupType deriving (Bits, Eq);

typedef enum {
  HmDirectionRequest,
  HmDirectionResponse,
  HmDirectionAny
} HmDirection deriving (Bits, Eq);

typedef 8 HmMaxPortsPerGroup;
typedef struct {
  HmPortGroupType groupType;
  Bit#(16) singlePort;
  Bit#(16) rangeStart;
  Bit#(16) rangeEnd;
  Vector#(HmMaxPortsPerGroup, Bit#(16)) listPorts;
  Bit#(4) listCount;
} HmPortGroup deriving (Bits, Eq);

typedef struct {
  Bool fpsmHit;
  Bool headerHit;
  Bool nfpsmHit;
  Bool finalHit;
  Bit#(32) firstRuleId;
  PrefilterRuleMask fpsmMask;
  PrefilterRuleMask headerMask;
  PrefilterRuleMask finalMask;
  Bit#(16) packetFingerprint;
  Bit#(8) bucketBitmap;
} PrefilterMatchResult deriving (Bits, Eq);

function HmPortGroup wildcardGroup();
  return HmPortGroup {
    groupType: HmPortGroupWildcard,
    singlePort: 0,
    rangeStart: 0,
    rangeEnd: 16'hffff,
    listPorts: replicate(0),
    listCount: 0
  };
endfunction

function Bool portInGroup(HmPortGroup group, Bit#(16) port);
  Bool out = False;
  case (group.groupType)
    HmPortGroupWildcard: out = True;
    HmPortGroupSingle: out = (port == group.singlePort);
    HmPortGroupRange: out = (port >= group.rangeStart) && (port <= group.rangeEnd);
    HmPortGroupList: begin
      out = False;
      for (Integer i = 0; i < valueOf(HmMaxPortsPerGroup); i = i + 1) begin
        if (fromInteger(i) < group.listCount && group.listPorts[i] == port) begin
          out = True;
        end
      end
    end
  endcase
  return out;
endfunction

endpackage: PrefilterTypes
