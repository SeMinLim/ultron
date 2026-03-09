package CuckooHashTable64;

import Vector::*;

import CuckooHash64::*;

typedef struct {
  Bool valid;
  Bit#(64) key;
  Bit#(64) value;
} CuckooEntry64 deriving (Bits);

interface CuckooTable64Ifc#(numeric type idxW);
  method Bool lookupHit(Bit#(64) key);
  method Bit#(64) lookupValue(Bit#(64) key);
  method Action insert(Bit#(64) key, Bit#(64) value);
endinterface

function CuckooEntry64 invalidEntry64();
  return CuckooEntry64 {
    valid: False,
    key: 0,
    value: 0
  };
endfunction

module mkCuckooHashTable64(CuckooTable64Ifc#(idxW))
  provisos (Add#(idxW, a__, 64));
  CuckooHash64Ifc#(idxW) hash <- mkCuckooHash64;

  Vector#(TExp#(idxW), Reg#(CuckooEntry64)) table1 <- replicateM(mkReg(invalidEntry64()));
  Vector#(TExp#(idxW), Reg#(CuckooEntry64)) table2 <- replicateM(mkReg(invalidEntry64()));
  Vector#(2, Reg#(CuckooEntry64)) stash <- replicateM(mkReg(invalidEntry64()));
  Reg#(Bit#(1)) stashReplacePtr <- mkReg(0);

  method Bool lookupHit(Bit#(64) key);
    Bit#(idxW) i1 = hash.h1(key);
    Bit#(idxW) i2 = hash.h2(key);
    let e1 = table1[i1];
    let e2 = table2[i2];

    Bool h1 = e1.valid && (e1.key == key);
    Bool h2 = e2.valid && (e2.key == key);
    Bool hs = False;
    for (Integer i = 0; i < 2; i = i + 1) begin
      let es = stash[i];
      if (es.valid && (es.key == key)) begin
        hs = True;
      end
    end
    return h1 || h2 || hs;
  endmethod

  method Bit#(64) lookupValue(Bit#(64) key);
    Bit#(idxW) i1 = hash.h1(key);
    Bit#(idxW) i2 = hash.h2(key);
    let e1 = table1[i1];
    let e2 = table2[i2];

    Bit#(64) out = 0;
    if (e1.valid && (e1.key == key)) begin
      out = e1.value;
    end else if (e2.valid && (e2.key == key)) begin
      out = e2.value;
    end else begin
      for (Integer i = 0; i < 2; i = i + 1) begin
        let es = stash[i];
        if (es.valid && (es.key == key)) begin
          out = es.value;
        end
      end
    end
    return out;
  endmethod

  method Action insert(Bit#(64) key, Bit#(64) value);
    Bit#(idxW) i1 = hash.h1(key);
    Bit#(idxW) i2 = hash.h2(key);

    let e1 = table1[i1];
    let e2 = table2[i2];

    CuckooEntry64 incoming = CuckooEntry64 {
      valid: True,
      key: key,
      value: value
    };

    Bool written = False;

    if (e1.valid && (e1.key == key)) begin
      table1[i1] <= incoming;
      written = True;
    end else if (e2.valid && (e2.key == key)) begin
      table2[i2] <= incoming;
      written = True;
    end else if (!e1.valid) begin
      table1[i1] <= incoming;
      written = True;
    end else if (!e2.valid) begin
      table2[i2] <= incoming;
      written = True;
    end

    if (!written) begin
      for (Integer i = 0; i < 2; i = i + 1) begin
        let es = stash[i];
        if (es.valid && (es.key == key)) begin
          stash[i] <= incoming;
          written = True;
        end
      end
    end

    if (!written) begin
      for (Integer i = 0; i < 2; i = i + 1) begin
        if (!stash[i].valid) begin
          stash[i] <= incoming;
          written = True;
        end
      end
    end

    if (!written) begin
      CuckooEntry64 kicked = e1;
      Bit#(idxW) k2 = hash.h2(kicked.key);
      let e2k = table2[k2];

      if (!e2k.valid || (e2k.key == kicked.key)) begin
        table1[i1] <= incoming;
        table2[k2] <= kicked;
      end else begin
        stash[stashReplacePtr] <= incoming;
        stashReplacePtr <= stashReplacePtr + 1;
      end
    end
  endmethod
endmodule

endpackage: CuckooHashTable64
