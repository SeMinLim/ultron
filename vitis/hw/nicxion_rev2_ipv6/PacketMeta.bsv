package PacketMeta;

import Vector::*;
import Types::*;

typedef struct {
    Bit#(32) srcIp;
    Bit#(32) dstIp;
    Bit#(8)  ipProto;
    Bit#(16) srcPort;
    Bit#(16) dstPort;
    Bit#(8)  icmpType;
    Bit#(8)  icmpCode;
} PktMetaFields deriving (Bits, Eq, FShow);

interface PacketMetaIfc;
    method Action   put(Epoch epoch, PktMetaFields m);
    method Bit#(8)  getProto(Epoch epoch);
    method Bit#(16) getSrcPort(Epoch epoch);
    method Bit#(16) getDstPort(Epoch epoch);
    method Bit#(8)  getIcmpType(Epoch epoch);
    method Bit#(8)  getIcmpCode(Epoch epoch);
endinterface

module mkPacketMeta(PacketMetaIfc);
    Vector#(NEpoch, Reg#(PktMetaFields)) cur <- replicateM(mkRegU);

    method Action put(Epoch epoch, PktMetaFields m);
        cur[epoch] <= m;
    endmethod

    method Bit#(8)  getProto(Epoch epoch)    = cur[epoch].ipProto;
    method Bit#(16) getSrcPort(Epoch epoch)  = cur[epoch].srcPort;
    method Bit#(16) getDstPort(Epoch epoch)  = cur[epoch].dstPort;
    method Bit#(8)  getIcmpType(Epoch epoch) = cur[epoch].icmpType;
    method Bit#(8)  getIcmpCode(Epoch epoch) = cur[epoch].icmpCode;
endmodule

endpackage
