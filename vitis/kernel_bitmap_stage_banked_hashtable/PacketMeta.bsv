package PacketMeta;

typedef struct {
    Bit#(8)  ipProto;
    Bit#(8)  flags;
    Bit#(16) srcPort;
    Bit#(16) dstPort;
    Bit#(8)  icmpType;
    Bit#(8)  icmpCode;
} PktMetaFields deriving (Bits, Eq, FShow);

interface PacketMetaIfc;
    method Action   put(PktMetaFields m);
    method Bit#(8)  getProto;
    method Bit#(16) getSrcPort;
    method Bit#(16) getDstPort;
    method Bit#(8)  getIcmpType;
    method Bit#(8)  getIcmpCode;
    method Bool     isTcp;
    method Bool     isUdp;
    method Bool     isIcmp;
endinterface

module mkPacketMeta(PacketMetaIfc);
    Reg#(PktMetaFields) cur <- mkReg(unpack(0));

    method Action put(PktMetaFields m);
        cur <= m;
    endmethod

    method Bit#(8)  getProto    = cur.ipProto;
    method Bit#(16) getSrcPort  = cur.srcPort;
    method Bit#(16) getDstPort  = cur.dstPort;
    method Bit#(8)  getIcmpType = cur.icmpType;
    method Bit#(8)  getIcmpCode = cur.icmpCode;
    method Bool     isTcp       = (cur.flags[0] == 1'b1);
    method Bool     isUdp       = (cur.flags[1] == 1'b1);
    method Bool     isIcmp      = (cur.flags[2] == 1'b1);
endmodule

endpackage
