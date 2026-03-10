package ParserTypes;

typedef struct {
  Bool valid;
  Bool supported;
  Bit#(8) protocol;
  Bit#(16) srcPort;
  Bit#(16) dstPort;
  Bit#(16) payloadOffset;
  Bit#(16) payloadLength;
  Bit#(64) payload64;
} PacketMeta deriving (Bits, Eq);

interface ParserIfc;
  method Action parse(Bit#(512) packetWord);
  method Bool metaValid;
  method PacketMeta metaFirst;
  method Action metaDeq;
endinterface

endpackage: ParserTypes
