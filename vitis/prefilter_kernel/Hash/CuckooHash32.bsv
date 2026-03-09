package CuckooHash32;

interface CuckooHashIfc#(numeric type idxW);
  method Bit#(idxW) h1(Bit#(32) k);
  method Bit#(idxW) h2(Bit#(32) k);
endinterface

function Bit#(idxW) modPow2(Bit#(32) k)
  provisos (Add#(idxW, a__, 32));
  return truncate(k);
endfunction

function Bit#(idxW) cuckoo_h1(Bit#(32) k)
  provisos (Add#(idxW, a__, 32));
  Bit#(32) mixed = k ^ (k >> 16);
  return modPow2(mixed);
endfunction

function Bit#(idxW) cuckoo_h2(Bit#(32) k)
  provisos (Add#(idxW, a__, 32));
  Bit#(32) mixed = (k * 32'h9e3779b1) ^ (k >> 13) ^ (k << 7);
  return truncate(mixed);
endfunction

module mkCuckooHash32(CuckooHashIfc#(idxW))
  provisos (Add#(idxW, a__, 32));
  method Bit#(idxW) h1(Bit#(32) k) = cuckoo_h1(k);
  method Bit#(idxW) h2(Bit#(32) k) = cuckoo_h2(k);
endmodule

endpackage: CuckooHash32
