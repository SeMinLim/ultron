package HashTable;

import CuckooHash::*;

interface HashTableIfc#(numeric type keySz, numeric type logSz);
	method Action clear;
	method Action insert(Bit#(keySz) key);
	
	method ActionValue#(Bool) insertAck;
	method Action queryReq(Bit#(keySz) key);
	method ActionValue#(Bool) queryResp;
	method Bool notBusy;
endinterface

module mkHashTable(HashTableIfc#(keySz, logSz))
	provisos(
		Add#(logSz, a__, keySz),
		Bits#(CuckooEntry#(keySz, 1), entrySz)
	);
	CuckooHashIfc#(keySz, 1, logSz) ht <- mkCuckooHash;

	method Action clear;
		ht.clear;
	endmethod

	method Action insert(Bit#(keySz) key);
		ht.insert(key, 1'b1);
	endmethod

	method ActionValue#(Bool) insertAck;
		let ok <- ht.insertAck;
		return ok;
	endmethod

	method Action queryReq(Bit#(keySz) key);
		ht.lookupReq(key);
	endmethod

	method ActionValue#(Bool) queryResp;
		let r <- ht.lookupResp;
		return isValid(r);
	endmethod

	method Bool notBusy;
		return ht.notBusy;
	endmethod
endmodule

endpackage
