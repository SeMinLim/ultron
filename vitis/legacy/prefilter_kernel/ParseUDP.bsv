package ParseUDP;

import PacketParserTypes::*;

function L4ParseResult parseUDP(Bit#(128) w2);
  Bit#(16) srcPort = getWord16BE(w2, 2);
  Bit#(16) dstPort = getWord16BE(w2, 4);
  return L4ParseResult{
    srcPort: srcPort,
    dstPort: dstPort,
    l4HeaderLen: 8
  };
endfunction

endpackage: ParseUDP
