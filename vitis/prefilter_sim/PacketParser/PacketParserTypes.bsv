package PacketParserTypes;

import PcieCtrl::*;

typedef struct {
  Bit#(8) protocol;
  Bit#(16) srcPort;
  Bit#(16) dstPort;
  Bit#(32) srcIp;
  Bit#(32) dstIp;
  Bit#(16) totalLength;
  Bit#(16) payloadOffset;
  Bit#(16) payloadLength;
} PacketMeta deriving (Bits, Eq);

interface PacketParserIfc;
  method Action enq(DMAWord data);
  method Bool payloadValid;
  method DMAWord payloadFirst;
  method Action payloadDeq;
  method Bool metaValid;
  method PacketMeta metaFirst;
  method Action metaDeq;
endinterface

typedef struct {
  Bit#(16) srcPort;
  Bit#(16) dstPort;
  Bit#(32) l4HeaderLen;
} L4ParseResult deriving (Bits, Eq);

function Bit#(8) getByte128(Bit#(128) w, Bit#(4) i);
  case (i)
    0:  return w[127:120];
    1:  return w[119:112];
    2:  return w[111:104];
    3:  return w[103:96];
    4:  return w[95:88];
    5:  return w[87:80];
    6:  return w[79:72];
    7:  return w[71:64];
    8:  return w[63:56];
    9:  return w[55:48];
    10: return w[47:40];
    11: return w[39:32];
    12: return w[31:24];
    13: return w[23:16];
    14: return w[15:8];
    15: return w[7:0];
    default: return 0;
  endcase
endfunction

function Bit#(16) getWord16BE(Bit#(128) w, Bit#(4) byteIdx);
  Bit#(8) b0 = getByte128(w, byteIdx);
  Bit#(8) b1 = getByte128(w, byteIdx + 1);
  return {b0, b1};
endfunction

function Bit#(32) getWord32BE(Bit#(128) w, Bit#(4) byteIdx);
  Bit#(8) b0 = getByte128(w, byteIdx);
  Bit#(8) b1 = getByte128(w, byteIdx + 1);
  Bit#(8) b2 = getByte128(w, byteIdx + 2);
  Bit#(8) b3 = getByte128(w, byteIdx + 3);
  return {b0, b1, b2, b3};
endfunction

endpackage: PacketParserTypes
