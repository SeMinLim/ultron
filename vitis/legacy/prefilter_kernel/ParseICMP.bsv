package ParseICMP;

import PacketParserTypes::*;

function L4ParseResult parseICMP(Bit#(128) w2);
  return L4ParseResult{
    srcPort: 0,
    dstPort: 0,
    l4HeaderLen: 8
  };
endfunction

endpackage: ParseICMP
