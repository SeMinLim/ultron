package Axi4MemoryMaster;

import FIFO::*;
import FIFOF::*;

interface Axi4MemoryMasterPinsIfc#(numeric type addrSz, numeric type dataSz);
	// write address to axi
	(* always_ready, result="awvalid" *)
	method Bool awvalid;
	(* always_ready, always_enabled, prefix = "" *)
	method Action address_write ((* port="awready" *)  Bool awready);
	(* always_ready, result="awaddr" *)
	method Bit#(addrSz) awaddr;
	(* always_ready, result="awlen" *)
	method Bit#(8) awlen;


	// write data to axi
	(* always_ready, result="wvalid" *)
	method Bool wvalid;
	(* always_ready, always_enabled, prefix = "" *)
	method Action data_write ((* port="wready" *)  Bool wready);
	(* always_ready, result="wdata" *)
	method Bit#(dataSz) wdata;
	(* always_ready, result="wstrb" *)
	method Bit#(TDiv#(dataSz,8)) wstrb;
	(* always_ready, result="wlast" *)
	method Bool wlast;


	// write response from axi
	(* always_ready, always_enabled, prefix = "" *)
	method Action write_resp_valid ((* port="bvalid" *)  Bool bvalid);
	(* always_ready, result="bready" *)
	method Bool bready;
	
	// write read addr to axi
	(* always_ready, result="arvalid" *)
	method Bool arvalid;
	(* always_ready, always_enabled, prefix = "" *)
	method Action read_address_ready ((* port="arready" *)  Bool arready);
	(* always_ready, result="araddr" *)
	method Bit#(addrSz) araddr;
	(* always_ready, result="arlen" *)
	method Bit#(8) arlen;


	// read response from axi
	(* always_ready, always_enabled, prefix = "" *)
	method Action read_data_valid ((* port="rvalid" *)  Bool rvalid);
	(* always_ready, result="rready" *)
	method Bool rready;
	(* always_ready, always_enabled, prefix = "" *)
	method Action read_data ((* port="rdata" *)  Bit#(dataSz) rdata);
	(* always_ready, always_enabled, prefix = "" *)
	method Action read_data_last ((* port="rlast" *)  Bool rlast);
endinterface

interface Axi4MemoryMasterIfc#(numeric type addrSz, numeric type dataSz);

	interface Axi4MemoryMasterPinsIfc#(addrSz,dataSz) pins;
  
	method Action readReq(Bit#(addrSz) addr, Bit#(addrSz) size);
	// ignoring tlast for simplicity
	method ActionValue#(Bit#(dataSz)) read;

	method Action writeReq(Bit#(addrSz) addr, Bit#(addrSz) size);
	method Action write(Bit#(dataSz) data);
  /*
  // read user interface
  output wire                          m_axis_tvalid,
  input  wire                          m_axis_tready,
  output wire [C_M_AXI_DATA_WIDTH-1:0] m_axis_tdata,
  output wire                          m_axis_tlast
  */

  /* 
  // write user interface
  input  wire                            s_axis_tvalid,
  output wire                            s_axis_tready,
  input  wire  [C_M_AXI_DATA_WIDTH-1:0]  s_axis_tdata
  */
endinterface

(* synthesize *)
module mkAxi4MemoryMaster_64_512 (Axi4MemoryMasterIfc#(64,512));
	let m_ <- mkAxi4MemoryMaster;
	return m_;
endmodule

module mkAxi4MemoryMaster (Axi4MemoryMasterIfc#(addrSz,dataSz))
	provisos(
		Add#(a__,8,addrSz),
		Add#(b__,512,dataSz)
	);
	Reg#(Bit#(16)) writeWordInflightDn <- mkReg(0);
	FIFOF#(Tuple2#(Bit#(addrSz), Bit#(addrSz))) writeBurstReqQ <- mkFIFOF;
	FIFOF#(Bit#(dataSz)) writeWordQ <- mkFIFOF;


	// max burst length = 64 for 512 bit words
	Integer maxBurstWords = min(256, (4096/(valueOf(dataSz)/8)));
	Integer maxBurstBytes = maxBurstWords*(valueOf(dataSz)/8);
	Integer wordByteSzBits = valueOf(TLog#(dataSz))-3; // -3 for bytes

	function Bit#(8) burstLenForBytes(Bit#(addrSz) sizeBytes);
		Bit#(addrSz) beats = (sizeBytes + fromInteger((valueOf(dataSz) / 8) - 1)) >> wordByteSzBits;
		return truncate(beats - 1);
	endfunction

	Reg#(Bit#(addrSz)) writeBurstCurAddr <- mkReg(0);
	Reg#(Bit#(addrSz)) writeBurstBytesLeft <- mkReg(0);

	FIFOF#(Tuple2#(Bit#(addrSz), Bit#(8))) writeBurstSubQ <- mkFIFOF;
	rule genBurst;
		if ( writeBurstBytesLeft > 0 ) begin
			writeBurstCurAddr <= writeBurstCurAddr + fromInteger(maxBurstBytes);
			if ( writeBurstBytesLeft > fromInteger(maxBurstBytes) ) begin
				writeBurstBytesLeft <= writeBurstBytesLeft - fromInteger(maxBurstBytes);

				writeBurstSubQ.enq(tuple2(writeBurstCurAddr, fromInteger(maxBurstWords-1))); // because 0 is one beat
			end else begin
				writeBurstSubQ.enq(tuple2(writeBurstCurAddr, burstLenForBytes(writeBurstBytesLeft))); // because 0 is one beat
				writeBurstBytesLeft <= 0;
			end
		end else begin
			writeBurstReqQ.deq;
			let r = writeBurstReqQ.first;
			let raddr = tpl_1(r);
			let rsz = tpl_2(r);
			if ( rsz > fromInteger(maxBurstBytes) ) begin
				writeBurstSubQ.enq(tuple2(raddr,fromInteger(maxBurstWords-1))); // because 0 is one beat
				writeBurstBytesLeft <= rsz - fromInteger(maxBurstBytes); 
				writeBurstCurAddr <= raddr + fromInteger(maxBurstBytes); 
			end else begin
				writeBurstSubQ.enq(tuple2(raddr,burstLenForBytes(rsz))); // because 0 is one beat
			end
		end
	endrule

	RWire#(Tuple2#(Bit#(addrSz),Bit#(8))) addressWriteW <- mkRWire;
	PulseWire addressWriteReadyW <- mkPulseWire;
	FIFO#(Bit#(8)) writeBurstCounterQ <- mkFIFO;
	rule applyAddressWrite;
		if ( addressWriteReadyW ) begin
			writeBurstSubQ.deq;
			addressWriteW.wset(writeBurstSubQ.first);
			writeBurstCounterQ.enq(tpl_2(writeBurstSubQ.first));
		end
	endrule


	RWire#(Tuple2#(Bit#(dataSz),Bool)) dataWriteW <- mkRWire;
	PulseWire dataWriteReadyW <- mkPulseWire;
	Reg#(Bit#(8)) curBurstLeft <- mkReg(0);
	rule applyDataWrite;
		if ( dataWriteReadyW ) begin
			Bit#(8) nextBurstLeft = ?;
			if ( curBurstLeft == 0 ) begin
				writeBurstCounterQ.deq;
				nextBurstLeft = writeBurstCounterQ.first ;
			end else begin
				nextBurstLeft = curBurstLeft - 1;
			end
			curBurstLeft <= nextBurstLeft;
			writeWordQ.deq;
			dataWriteW.wset(tuple2(writeWordQ.first, nextBurstLeft == 0 ));
		end
	endrule
	
	FIFOF#(Tuple2#(Bit#(addrSz), Bit#(addrSz))) readBurstReqQ <- mkFIFOF;
	Reg#(Bit#(addrSz)) readBurstCurAddr <- mkReg(0);
	Reg#(Bit#(addrSz)) readBurstBytesLeft <- mkReg(0);
	
	FIFOF#(Tuple2#(Bit#(addrSz), Bit#(8))) readBurstSubQ <- mkFIFOF;
	rule genReadBurst;
		if ( readBurstBytesLeft > 0 ) begin
			readBurstCurAddr <= readBurstCurAddr + fromInteger(maxBurstBytes);
			if ( readBurstBytesLeft > fromInteger(maxBurstBytes) ) begin
				readBurstBytesLeft <= readBurstBytesLeft - fromInteger(maxBurstBytes);

				readBurstSubQ.enq(tuple2(readBurstCurAddr, fromInteger(maxBurstWords-1))); // because 0 is one beat
			end else begin
				readBurstSubQ.enq(tuple2(readBurstCurAddr, burstLenForBytes(readBurstBytesLeft))); // because 0 is one beat
				readBurstBytesLeft <= 0;
			end
		end else begin
			readBurstReqQ.deq;
			let r = readBurstReqQ.first;
			let raddr = tpl_1(r);
			let rsz = tpl_2(r);
			if ( rsz > fromInteger(maxBurstBytes) ) begin
				readBurstSubQ.enq(tuple2(raddr,fromInteger(maxBurstWords-1))); // because 0 is one beat
				readBurstBytesLeft <= rsz - fromInteger(maxBurstBytes); 
				readBurstCurAddr <= raddr + fromInteger(maxBurstBytes); 
			end else begin
				readBurstSubQ.enq(tuple2(raddr,burstLenForBytes(rsz))); // because 0 is one beat
			end
		end
	endrule

	// AXI4 requires arvalid to stay asserted until arready.
	// Use a register to hold the pending address, so arvalid stays True
	// even if arready arrives many cycles after readBurstSubQ is populated.
	PulseWire         readAddressReadyW <- mkPulseWire;
	Reg#(Bool)        readAddrValid     <- mkReg(False);
	Reg#(Bit#(addrSz)) readAddrAddr    <- mkRegU;
	Reg#(Bit#(8))     readAddrLen      <- mkRegU;

	rule loadReadAddr(!readAddrValid && readBurstSubQ.notEmpty);
		let item = readBurstSubQ.first;
		readBurstSubQ.deq;
		readAddrAddr  <= tpl_1(item);
		readAddrLen   <= tpl_2(item);
		readAddrValid <= True;
	endrule

	rule clearReadAddr(readAddrValid && readAddressReadyW);
		readAddrValid <= False;
	endrule
	
	PulseWire readDataValidW <- mkPulseWire;
	PulseWire readDataReadyW <- mkPulseWire;
	FIFOF#(Bit#(dataSz)) readWordQ <- mkSizedFIFOF(32);
	RWire#(Bit#(dataSz)) readDataWordW <- mkRWire;
	rule handleReadWord;
		if ( readWordQ.notFull ) begin
			readDataReadyW.send;

			if ( readDataValidW ) begin
			//if ( isValid(readDataWordW.wget) ) begin
				readWordQ.enq(fromMaybe(?,readDataWordW.wget));
			end
		end
	endrule

	interface Axi4MemoryMasterPinsIfc pins;
		method Bool awvalid;
			return isValid(addressWriteW.wget);
		endmethod
		method Action address_write (Bool awready);
			if ( awready ) addressWriteReadyW.send;
		endmethod
		method Bit#(addrSz) awaddr;
			let a = fromMaybe(?,addressWriteW.wget);
			return tpl_1(a);
		endmethod
		method Bit#(8) awlen;
			let a = fromMaybe(?,addressWriteW.wget);
			return tpl_2(a);
		endmethod
	
		method Bool wvalid;
			return isValid(dataWriteW.wget);
		endmethod
		method Action data_write ( Bool wready);
			if (wready) dataWriteReadyW.send;
		endmethod
		method Bit#(dataSz) wdata;
			let d = fromMaybe(?,dataWriteW.wget);
			return tpl_1(d);
		endmethod
		method Bit#(TDiv#(dataSz,8)) wstrb;
			return (-1);
		endmethod
		method Bool wlast;
			let d = fromMaybe(?,dataWriteW.wget);
			return tpl_2(d);
		endmethod
	
		method Action write_resp_valid (Bool bvalid);
			if ( bvalid ) writeWordInflightDn <= writeWordInflightDn + 1;
		endmethod
		method Bool bready;
			return True;
		endmethod
	
		// write read addr to axi
		method Bool arvalid;
			return readAddrValid;
		endmethod
		method Action read_address_ready ( Bool arready);
			if ( arready && readAddrValid ) readAddressReadyW.send;
		endmethod
		method Bit#(addrSz) araddr;
			return readAddrAddr;
		endmethod
		method Bit#(8) arlen;
			return readAddrLen;
		endmethod


		// read response from axi
		method Action read_data_valid ( Bool rvalid);
			if ( rvalid ) readDataValidW.send;
		endmethod
		method Bool rready;
			return readDataReadyW;
		endmethod
		method Action read_data (Bit#(dataSz) rdata);
			readDataWordW.wset(rdata);
		endmethod
		method Action read_data_last (Bool rlast);
		endmethod
	endinterface

	method Action readReq(Bit#(addrSz) addr, Bit#(addrSz) size);
		readBurstReqQ.enq(tuple2(addr,size));
	endmethod
	method ActionValue#(Bit#(dataSz)) read;
		readWordQ.deq;
		return readWordQ.first;
	endmethod

	method Action writeReq(Bit#(addrSz) addr, Bit#(addrSz) size);
		writeBurstReqQ.enq(tuple2(addr,size));
	endmethod
	method Action write(Bit#(dataSz) data);
		writeWordQ.enq(data);
	endmethod
endmodule


endpackage
