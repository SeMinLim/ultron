package GramIdTable;

// URAM-backed gram→rule-metadata table.
// CuckooHash#(32, 40, 14): keySz=32 (gram), valSz=40 (RuleInfo packed), logSz=14.
// In synthesis, RegFile with 2^14 × (32+1+40) entries maps to URAM banks.
// Requires keySz >= 2*logSz: 32 >= 28. OK.
//
// RuleInfo packed as 40-bit cuckoo value:
//   [39:24] ruleId  [23:16] pre (int8)  [15:8] post (int8)  [7:0] len

import CuckooHash::*;

typedef struct {
    Bit#(16) ruleId;
    Int#(8)  pre;
    Int#(8)  post;
    Bit#(8)  len;
} RuleInfo deriving (Bits, Eq, FShow);

interface GramIdTableIfc;
    method Action insert(Bit#(32) gram, RuleInfo info);
    method ActionValue#(Bool) insertAck;
    method Bool notBusy;
    method Action lookupReq(Bit#(32) gram);
    method ActionValue#(Maybe#(RuleInfo)) lookupResp;
endinterface

(* synthesize *)
module mkGramIdTable(GramIdTableIfc);
    CuckooHashIfc#(32, 40, 14) ht <- mkCuckooHash;

    method Action insert(Bit#(32) gram, RuleInfo info);
        ht.insert(gram, pack(info));
    endmethod

    method ActionValue#(Bool) insertAck = ht.insertAck;
    method Bool notBusy = ht.notBusy;

    method Action lookupReq(Bit#(32) gram);
        ht.lookupReq(gram);
    endmethod

    method ActionValue#(Maybe#(RuleInfo)) lookupResp;
        let r <- ht.lookupResp;
        case (r) matches
            tagged Valid .v: return tagged Valid unpack(v);
            tagged Invalid:  return tagged Invalid;
        endcase
    endmethod
endmodule

endpackage
