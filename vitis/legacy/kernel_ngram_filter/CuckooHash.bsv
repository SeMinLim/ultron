package CuckooHash;

// ref: https://www.geeksforgeeks.org/dsa/cuckoo-hashing/

import FIFO::*;
import FIFOF::*;
import RegFile::*;

typedef struct {
	Bool        valid;
	Bit#(keySz) key;
	Bit#(valSz) val;
} CuckooEntry#(numeric type keySz, numeric type valSz) deriving (Bits, Eq);

interface CuckooHashIfc#(numeric type keySz, numeric type valSz, numeric type logSz);
	method Action clear;
	method Action insert(Bit#(keySz) key, Bit#(valSz) val);
	method ActionValue#(Bool) insertAck;
	method Action lookupReq(Bit#(keySz) key);
	method ActionValue#(Maybe#(Bit#(valSz))) lookupResp;
	method Bool notBusy;
endinterface

typedef enum { HT_CLEAR, HT_IDLE, HT_INSERTING } HtState deriving (Bits, Eq);
typedef 16 MaxEvictions;

module mkCuckooHash(CuckooHashIfc#(keySz, valSz, logSz))
	provisos(
		Add#(logSz, a__, keySz),
		Bits#(CuckooEntry#(keySz, valSz), entrySz)
	);

	RegFile#(Bit#(logSz), CuckooEntry#(keySz, valSz)) table0 <- mkRegFileFull;
	RegFile#(Bit#(logSz), CuckooEntry#(keySz, valSz)) table1 <- mkRegFileFull;

	Reg#(HtState)     htState  <- mkReg(HT_CLEAR);
	Reg#(Bit#(keySz)) pendKey  <- mkReg(0);
	Reg#(Bit#(valSz)) pendVal  <- mkReg(0);
	Reg#(Bool)        useAlt   <- mkReg(False);
	Reg#(UInt#(5))    evictCnt <- mkReg(0);

	Reg#(Bit#(logSz)) clearIdx <- mkReg(0);
	Reg#(Bool)        clearAlt <- mkReg(False);

	FIFOF#(Bool)                 insertAckQ  <- mkFIFOF;
	FIFOF#(Bit#(keySz))         lookupReqQ  <- mkSizedFIFOF(128);
	FIFOF#(Maybe#(Bit#(valSz))) lookupRespQ <- mkSizedFIFOF(128);

	function Bit#(logSz) h0(Bit#(keySz) k) = truncate(k);
	function Bit#(logSz) h1(Bit#(keySz) k) = truncate(k >> fromInteger(valueOf(logSz)));

	CuckooEntry#(keySz, valSz) emptyEntry = CuckooEntry { valid: False, key: 0, val: 0 };

	rule doClear (htState == HT_CLEAR);
		if (!clearAlt) begin
			table0.upd(clearIdx, emptyEntry);
			if (clearIdx == maxBound) clearAlt <= True;
			clearIdx <= clearIdx + 1;
		end else begin
			table1.upd(clearIdx, emptyEntry);
			if (clearIdx == maxBound) begin
				htState  <= HT_IDLE;
				clearAlt <= False;
			end
			clearIdx <= clearIdx + 1;
		end
	endrule

	rule doLookup (htState == HT_IDLE && lookupReqQ.notEmpty);
		let key = lookupReqQ.first;
		lookupReqQ.deq;
		let e0 = table0.sub(h0(key));
		let e1 = table1.sub(h1(key));
		if      (e0.valid && e0.key == key) lookupRespQ.enq(tagged Valid e0.val);
		else if (e1.valid && e1.key == key) lookupRespQ.enq(tagged Valid e1.val);
		else                                lookupRespQ.enq(tagged Invalid);
	endrule

	rule doInsert (htState == HT_INSERTING);
		Bit#(logSz)                idx      = useAlt ? h1(pendKey) : h0(pendKey);
		CuckooEntry#(keySz, valSz) existing = useAlt ? table1.sub(idx) : table0.sub(idx);
		CuckooEntry#(keySz, valSz) newEntry = CuckooEntry { valid: True,
		                                                     key:   pendKey,
		                                                     val:   pendVal };

		if (!existing.valid || existing.key == pendKey) begin
			if (useAlt) table1.upd(idx, newEntry);
			else        table0.upd(idx, newEntry);
			insertAckQ.enq(True);
			htState  <= HT_IDLE;
			evictCnt <= 0;
		end else if (evictCnt < fromInteger(valueOf(MaxEvictions))) begin
			if (useAlt) table1.upd(idx, newEntry);
			else        table0.upd(idx, newEntry);
			pendKey  <= existing.key;
			pendVal  <= existing.val;
			useAlt   <= !useAlt;
			evictCnt <= evictCnt + 1;
		end else begin
			insertAckQ.enq(False);
			htState  <= HT_IDLE;
			evictCnt <= 0;
		end
	endrule

	method Action clear if (htState == HT_IDLE);
		htState <= HT_CLEAR;
	endmethod

	method Action insert(Bit#(keySz) key, Bit#(valSz) val) if (htState == HT_IDLE);
		pendKey <= key;
		pendVal <= val;
		useAlt  <= False;
		htState <= HT_INSERTING;
	endmethod

	method ActionValue#(Bool) insertAck;
		let v = insertAckQ.first; insertAckQ.deq; return v;
	endmethod

	method Action lookupReq(Bit#(keySz) key);
		lookupReqQ.enq(key);
	endmethod

	method ActionValue#(Maybe#(Bit#(valSz))) lookupResp;
		let v = lookupRespQ.first; lookupRespQ.deq; return v;
	endmethod

	method Bool notBusy;
		return htState == HT_IDLE;
	endmethod
endmodule

endpackage
