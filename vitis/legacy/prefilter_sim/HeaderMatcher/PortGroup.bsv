import BRAM::*;
import Vector::*;

typedef Bit#(16) RuleId;
typedef Bit#(16) PortNumber;
typedef Bit#(8) ProtocolType;

typedef struct {
    PortNumber srcPortMin;
    PortNumber srcPortMax;
    PortNumber dstPortMin;
    PortNumber dstPortMax;
    ProtocolType protocol;
} PortGroupSpec deriving (Bits, Eq);

typedef struct {
    PortNumber srcPort;
    PortNumber dstPort;
    ProtocolType protocol;
} PacketHeader deriving (Bits, Eq);

interface PortGroupIfc;
    method Action loadPortGroup(RuleId ruleId, PortGroupSpec spec);
    method ActionValue#(Bool) checkMatch(RuleId ruleId, PacketHeader pktHdr);
endinterface

module mkPortGroup(PortGroupIfc);
    BRAM_Configure bramCfg = defaultValue;
    bramCfg.latency = 1;
    BRAM1Port#(Bit#(10), PortGroupSpec) portGroupTable <- mkBRAM1Server(bramCfg);

    method Action loadPortGroup(RuleId ruleId, PortGroupSpec spec);
        Bit#(10) addr = truncate(ruleId);
        portGroupTable.portA.request.put(BRAMRequest{
            write: True,
            responseOnWrite: False,
            address: addr,
            datain: spec
        });
    endmethod

    method ActionValue#(Bool) checkMatch(RuleId ruleId, PacketHeader pktHdr);
        Bit#(10) addr = truncate(ruleId);
        portGroupTable.portA.request.put(BRAMRequest{
            write: False,
            responseOnWrite: False,
            address: addr,
            datain: ?
        });
        let spec <- portGroupTable.portA.response.get();

        Bool srcPortMatch = (pktHdr.srcPort >= spec.srcPortMin) &&
                           (pktHdr.srcPort <= spec.srcPortMax);
        Bool dstPortMatch = (pktHdr.dstPort >= spec.dstPortMin) &&
                           (pktHdr.dstPort <= spec.dstPortMax);
        Bool protocolMatch = (spec.protocol == 0) ||
                            (spec.protocol == pktHdr.protocol);

        return srcPortMatch && dstPortMatch && protocolMatch;
    endmethod
endmodule
