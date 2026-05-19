package PacketMeta;

import Vector::*;

typedef struct {
    Bit#(8)  ipProto;
    Bit#(8)  flags;
    Bit#(16) srcPort;
    Bit#(16) dstPort;
    Bit#(8)  icmpType;
    Bit#(8)  icmpCode;
} PktMetaFields deriving (Bits, Eq, FShow);

interface PacketMetaIfc;
    method Action   put(Bit#(3) epoch, PktMetaFields m);
    method Bit#(8)  getProto(Bit#(3) epoch);
    method Bit#(16) getSrcPort(Bit#(3) epoch);
    method Bit#(16) getDstPort(Bit#(3) epoch);
    method Bit#(8)  getIcmpType(Bit#(3) epoch);
    method Bit#(8)  getIcmpCode(Bit#(3) epoch);
    method Bool     isTcp(Bit#(3) epoch);
    method Bool     isUdp(Bit#(3) epoch);
    method Bool     isIcmp(Bit#(3) epoch);
endinterface

module mkPacketMeta(PacketMetaIfc);
    Vector#(8, Reg#(PktMetaFields)) cur <- replicateM(mkReg(unpack(0)));

    method Action put(Bit#(3) epoch, PktMetaFields m);
        cur[epoch] <= m;
    endmethod

    method Bit#(8)  getProto(Bit#(3) epoch)    = cur[epoch].ipProto;
    method Bit#(16) getSrcPort(Bit#(3) epoch)  = cur[epoch].srcPort;
    method Bit#(16) getDstPort(Bit#(3) epoch)  = cur[epoch].dstPort;
    method Bit#(8)  getIcmpType(Bit#(3) epoch) = cur[epoch].icmpType;
    method Bit#(8)  getIcmpCode(Bit#(3) epoch) = cur[epoch].icmpCode;
    method Bool     isTcp(Bit#(3) epoch)       = (cur[epoch].flags[1] == 1'b1);
    method Bool     isUdp(Bit#(3) epoch)       = (cur[epoch].flags[2] == 1'b1);
    method Bool     isIcmp(Bit#(3) epoch)      = (cur[epoch].flags[3] == 1'b1);
endmodule

endpackage
