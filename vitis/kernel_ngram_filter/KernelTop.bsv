package KernelTop;

import Axi4LiteControllerXrt::*;
import Axi4MemoryMaster::*;

import FIFO::*;
import Vector::*;
import Clocks :: *;

import KernelMain::*;


interface KernelTopIfc;
	(* always_ready *)
	interface Axi4MemoryMasterPinsIfc#(64,512) db;
	(* always_ready *)
	interface Axi4MemoryMasterPinsIfc#(64,512) pkt;
	(* always_ready *)
	interface Axi4MemoryMasterPinsIfc#(64,512) result;
	(* always_ready *)
	interface Axi4LiteControllerXrtPinsIfc#(12,32) s_axi_control;
	(* always_ready *)
	method Bool interrupt;
endinterface
(* synthesize *)
(* default_reset="ap_rst_n", default_clock_osc="ap_clk" *)
module kernel (KernelTopIfc);
	Clock defaultClock <- exposeCurrentClock;
	Reset defaultReset <- exposeCurrentReset;

	Axi4LiteControllerXrtIfc#(12,32) axi4control <- mkAxi4LiteControllerXrt(defaultClock, defaultReset);
	Vector#(MemPortCnt, Axi4MemoryMasterIfc#(64,512)) axi4mem <- replicateM(mkAxi4MemoryMaster_64_512);
	KernelMainIfc kernelMain <- mkKernelMain;

	Reg#(Bool) started <- mkReg(False);
	rule assertControl;
		if ( !started ) begin
			axi4control.ap_idle;
		end
	endrule

	Reg#(Bool) last_ap_start <- mkReg(False);
	rule sampleApStart ( last_ap_start != axi4control.ap_start );
		last_ap_start <= axi4control.ap_start;
	endrule

	rule checkStart ( !last_ap_start && axi4control.ap_start && !started );
		kernelMain.start(
			axi4control.pktCount,
			axi4control.dbBytes,
			axi4control.dbBase,
			axi4control.pktBase,
			axi4control.resultBase
		);
		started <= True;
	endrule

	rule checkDone ( started );
		Bool done <- kernelMain.done;
		if ( done ) begin
			axi4control.ap_done();
			axi4control.ap_ready;
			started <= False;
		end
	endrule
	

	for ( Integer i = 0; i < valueOf(MemPortCnt); i=i+1 ) begin
		rule relayReadReq ( started );
			let r <- kernelMain.mem[i].readReq;
			axi4mem[i].readReq(r.addr, r.bytes);
		endrule
		rule relayWriteReq ( started );
			let r <- kernelMain.mem[i].writeReq;
			axi4mem[i].writeReq(r.addr, r.bytes);
		endrule
		rule relayWriteWord ( started );
			let r <- kernelMain.mem[i].writeWord;
			axi4mem[i].write(r);
		endrule
		rule relayReadWord ( started );
			let d <- axi4mem[i].read;
			kernelMain.mem[i].readWord(d);
		endrule
	end


	interface db = axi4mem[0].pins;
	interface pkt = axi4mem[1].pins;
	interface result = axi4mem[2].pins;
	interface s_axi_control = axi4control.pins;
	interface interrupt = axi4control.interrupt;
endmodule

endpackage
