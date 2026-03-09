package CuckooHashTable;

import Vector::*;

import CuckooHash32::*;

typedef struct {
  Bool valid;
  Bit#(32) key;
  Bit#(32) value;
} CuckooEntry deriving (Bits);

interface CuckooTableIfc#(numeric type idxW);
  method Bool lookupHit(Bit#(32) key);
  method Bit#(32) lookupValue(Bit#(32) key);
  method Action insert(Bit#(32) key, Bit#(32) value);
endinterface

function CuckooEntry invalidEntry();
  return CuckooEntry {
    valid: False,
    key: 0,
    value: ?
  };
endfunction

module mkCuckooHashTable(CuckooTableIfc#(idxW))
  provisos (Add#(idxW, a__, 32));
  CuckooHashIfc#(idxW) hash <- mkCuckooHash32;

  Vector#(TExp#(idxW), Reg#(CuckooEntry)) table1 <- replicateM(mkReg(invalidEntry()));
  Vector#(TExp#(idxW), Reg#(CuckooEntry)) table2 <- replicateM(mkReg(invalidEntry()));

  method Bool lookupHit(Bit#(32) key);
    Bit#(idxW) i1 = hash.h1(key);
    Bit#(idxW) i2 = hash.h2(key);
    let e1 = table1[i1];
    let e2 = table2[i2];

    Bool h1 = e1.valid && (e1.key == key);
    Bool h2 = e2.valid && (e2.key == key);
    return h1 || h2;
  endmethod

  method Bit#(32) lookupValue(Bit#(32) key);
    Bit#(idxW) i1 = hash.h1(key);
    Bit#(idxW) i2 = hash.h2(key);
    let e1 = table1[i1];
    let e2 = table2[i2];

    Bit#(32) out = 0;
    if (e1.valid && (e1.key == key)) begin
      out = e1.value;
    end else if (e2.valid && (e2.key == key)) begin
      out = e2.value;
    end
    return out;
  endmethod

  method Action insert(Bit#(32) key, Bit#(32) value);
    Bit#(idxW) i1 = hash.h1(key);
    Bit#(idxW) i2 = hash.h2(key);

    let e1 = table1[i1];
    let e2 = table2[i2];

    CuckooEntry incoming = CuckooEntry {
      valid: True,
      key: key,
      value: value
    };

    if (e1.valid && (e1.key == key)) begin
      table1[i1] <= incoming;
    end else if (e2.valid && (e2.key == key)) begin
      table2[i2] <= incoming;
    end else if (!e1.valid) begin
      table1[i1] <= incoming;
    end else if (!e2.valid) begin
      table2[i2] <= incoming;
    end else begin
      CuckooEntry kicked = e1;
      Bit#(idxW) k2 = hash.h2(kicked.key);
      let e2k = table2[k2];

      if (!e2k.valid || (e2k.key == kicked.key)) begin
        table1[i1] <= incoming;
        table2[k2] <= kicked;
      end
    end
  endmethod
endmodule

endpackage: CuckooHashTable
