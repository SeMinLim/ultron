package ParseTCP;

import PacketParserTypes::*;

function L4ParseResult parseTCP(Bit#(128) w2);
  Bit#(16) srcPort = getWord16BE(w2, 2);
  Bit#(16) dstPort = getWord16BE(w2, 4);
  Bit#(8) dataOffsetByte = getByte128(w2, 14);
  Bit#(4) dataOffsetWords = dataOffsetByte[7:4];
  Bit#(32) l4HeaderLen = zeroExtend(dataOffsetWords) << 2;
  return L4ParseResult{
    srcPort: srcPort,
    dstPort: dstPort,
    l4HeaderLen: l4HeaderLen
  };
endfunction

endpackage: ParseTCP
