package CuckooHash64;

interface CuckooHash64Ifc#(numeric type idxW);
  method Bit#(idxW) h1(Bit#(64) k);
  method Bit#(idxW) h2(Bit#(64) k);
endinterface

function Bit#(idxW) modPow2_64(Bit#(64) k)
  provisos (Add#(idxW, a__, 64));
  return truncate(k);
endfunction

function Bit#(idxW) cuckoo64_h1(Bit#(64) k)
  provisos (Add#(idxW, a__, 64));
  Bit#(64) mixed = k ^ (k >> 32);
  return modPow2_64(mixed);
endfunction

function Bit#(idxW) cuckoo64_h2(Bit#(64) k)
  provisos (Add#(idxW, a__, 64));
  Bit#(64) mixed = (k * 64'h9e3779b97f4a7c15) ^ (k >> 17) ^ (k << 11);
  return truncate(mixed);
endfunction

module mkCuckooHash64(CuckooHash64Ifc#(idxW))
  provisos (Add#(idxW, a__, 64));
  method Bit#(idxW) h1(Bit#(64) k) = cuckoo64_h1(k);
  method Bit#(idxW) h2(Bit#(64) k) = cuckoo64_h2(k);
endmodule

endpackage: CuckooHash64
