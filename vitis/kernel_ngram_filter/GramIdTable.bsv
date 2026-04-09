package GramIdTable;


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
