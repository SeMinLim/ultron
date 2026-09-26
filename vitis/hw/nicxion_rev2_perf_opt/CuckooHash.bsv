package CuckooHash;

import BRAM::*;
import FIFO::*;
import FIFOF::*;

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
endinterface

typedef enum { HT_CLEAR, HT_IDLE, HT_INS_REQ, HT_INS_RESP, HT_INS_DEC } HtState deriving (Bits, Eq);
typedef 16 MaxEvictions;

module mkCuckooHash(CuckooHashIfc#(keySz, valSz, logSz))
	provisos(
		Add#(logSz, a__, keySz),
		Add#(logSz, b__, 12),                 // 2^(logSz+1) fits the 12-bit address
		Bits#(CuckooEntry#(keySz, valSz), entrySz)
	);

	// Depth follows logSz: table0 @ [0 .. 2^logSz-1] (portA),
	// table1 @ [2^logSz .. 2^(logSz+1)-1] (portB).
	BRAM_Configure cfg = defaultValue;
	cfg.memorySize = 2 * valueOf(TExp#(logSz));
	cfg.latency    = 2;
	BRAM2Port#(Bit#(12), CuckooEntry#(keySz, valSz)) ram <- mkBRAM2Server(cfg);

	Reg#(HtState)     htState  <- mkReg(HT_CLEAR);
	Reg#(Bit#(keySz)) pendKey  <- mkRegU;
	Reg#(Bit#(valSz)) pendVal  <- mkRegU;
	Reg#(CuckooEntry#(keySz, valSz)) insExisting <- mkRegU;   // slot read, decided next cycle
	Reg#(Bool)        useAlt   <- mkReg(False);
	Reg#(UInt#(5))    evictCnt <- mkReg(0);
	Reg#(Bit#(12))    insAddr  <- mkRegU;       // address being read/written this evict step

	Reg#(Bit#(logSz)) clearIdx <- mkReg(0);
	Reg#(Bool)        clearAlt <- mkReg(False);

	FIFOF#(Bool)                 insertAckQ  <- mkFIFOF;
	FIFOF#(Tuple2#(Bit#(keySz), Bit#(valSz))) insReqQ <- mkFIFOF;
	FIFOF#(Bit#(keySz))         lookupReqQ  <- mkSizedFIFOF(8);
	FIFOF#(Bit#(keySz))         lkKeyPipe   <- mkSizedFIFOF(4);  // keys awaiting RAM resp
	FIFOF#(Maybe#(Bit#(valSz))) lookupRespQ <- mkSizedFIFOF(8);

	function Bit#(logSz) h0(Bit#(keySz) k);
		Bit#(keySz) x = k ^ (k >> fromInteger(valueOf(logSz)));
		x = x ^ (x >> 7);
		x = x ^ (x << 11);
		return truncate(x);
	endfunction
	function Bit#(logSz) h1(Bit#(keySz) k);
		Bit#(keySz) x = k ^ (k << 5) ^ (k >> 13);
		x = x ^ (x << 9);
		x = x ^ (x >> 17);
		return truncate(x);
	endfunction
	// table0 address = h0; table1 address = 2^logSz + h1.
	Bit#(12) tbl1Base = fromInteger(valueOf(TExp#(logSz)));
	function Bit#(12) a0(Bit#(keySz) k) = zeroExtend(h0(k));
	function Bit#(12) a1(Bit#(keySz) k) = tbl1Base + zeroExtend(h1(k));

	CuckooEntry#(keySz, valSz) emptyEntry = CuckooEntry { valid: False, key: 0, val: 0 };

	function BRAMRequest#(Bit#(12), CuckooEntry#(keySz, valSz))
	         rd(Bit#(12) a) = BRAMRequest { write: False, responseOnWrite: False,
	                                        address: a, datain: ? };
	function BRAMRequest#(Bit#(12), CuckooEntry#(keySz, valSz))
	         wr(Bit#(12) a, CuckooEntry#(keySz, valSz) e) =
	             BRAMRequest { write: True, responseOnWrite: False, address: a, datain: e };

	// Clear both tables (portA: table0 region, portB: table1 region) in lockstep.
	rule doClear (htState == HT_CLEAR);
		ram.portA.request.put(wr(zeroExtend(clearIdx), emptyEntry));
		ram.portB.request.put(wr(tbl1Base + zeroExtend(clearIdx), emptyEntry));
		if (clearIdx == maxBound) begin
			htState  <= HT_IDLE;
			clearIdx <= 0;
		end else
			clearIdx <= clearIdx + 1;
	endrule

	// ---- Lookup: issue (read both tables) -> complete (compare) ----
	// Explicit notFull/notEmpty guards removed: the FIFO methods carry them, and
	// the explicit reads made lkIssue and lkComplete mutually exclusive.
	rule lkIssue (htState == HT_IDLE);
		let key = lookupReqQ.first; lookupReqQ.deq;
		ram.portA.request.put(rd(a0(key)));   // table0 @ h0
		ram.portB.request.put(rd(a1(key)));   // table1 @ h1
		lkKeyPipe.enq(key);
	endrule

	rule lkComplete (htState == HT_IDLE);
		let key = lkKeyPipe.first; lkKeyPipe.deq;
		let e0 <- ram.portA.response.get;
		let e1 <- ram.portB.response.get;
		if      (e0.valid && e0.key == key) lookupRespQ.enq(tagged Valid e0.val);
		else if (e1.valid && e1.key == key) lookupRespQ.enq(tagged Valid e1.val);
		else                                lookupRespQ.enq(tagged Invalid);
	endrule

	(* descending_urgency = "insStart, lkIssue" *)
	rule insStart (htState == HT_IDLE && !lkKeyPipe.notEmpty);
		match { .key, .val } = insReqQ.first; insReqQ.deq;
		pendKey <= key;
		pendVal <= val;
		useAlt  <= False;
		htState <= HT_INS_REQ;
	endrule

	rule insReq (htState == HT_INS_REQ);
		Bit#(12) a = useAlt ? a1(pendKey) : a0(pendKey);
		insAddr <= a;
		if (useAlt) ram.portB.request.put(rd(a));
		else        ram.portA.request.put(rd(a));
		htState <= HT_INS_RESP;
	endrule

	rule insResp (htState == HT_INS_RESP);
		CuckooEntry#(keySz, valSz) e;
		if (useAlt) e <- ram.portB.response.get;
		else        e <- ram.portA.response.get;
		insExisting <= e;
		htState     <= HT_INS_DEC;
	endrule

	rule insDecide (htState == HT_INS_DEC);
		CuckooEntry#(keySz, valSz) existing = insExisting;

		CuckooEntry#(keySz, valSz) newEntry = CuckooEntry { valid: True,
		                                                     key:   pendKey,
		                                                     val:   pendVal };
		function Action writeSlot(CuckooEntry#(keySz, valSz) e);
			action
				if (useAlt) ram.portB.request.put(wr(insAddr, e));
				else        ram.portA.request.put(wr(insAddr, e));
			endaction
		endfunction

		if (!existing.valid || existing.key == pendKey) begin
			writeSlot(newEntry);
			insertAckQ.enq(True);
			htState  <= HT_IDLE;
			evictCnt <= 0;
		end else if (evictCnt < fromInteger(valueOf(MaxEvictions))) begin
			writeSlot(newEntry);            // displace, then re-home the evicted key
			pendKey  <= existing.key;
			pendVal  <= existing.val;
			useAlt   <= !useAlt;
			evictCnt <= evictCnt + 1;
			htState  <= HT_INS_REQ;
		end else begin
			insertAckQ.enq(False);
			htState  <= HT_IDLE;
			evictCnt <= 0;
		end
	endrule

	method Action clear if (htState == HT_IDLE);
		htState <= HT_CLEAR;
	endmethod

	method Action insert(Bit#(keySz) key, Bit#(valSz) val);
		insReqQ.enq(tuple2(key, val));
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

endmodule

endpackage
