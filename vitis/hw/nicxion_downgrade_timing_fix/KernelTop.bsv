package KernelTop;

import AxiStream::*;
import Clocks :: *;

import KernelMain::*;

// Free-running PM kernel (ap_ctrl_none): no s_axi_control, no ap_start/ap_done.
// The kernel self-boots out of reset, loads the rule DB off s_axis_db, then
// matches packets forever. All data is AXI4-Stream (Req 1/2/3/4):
//   s_axis_db      = rule DB push (DB Master->Slave)
//   s_axis_pkt     = packet input (payload + 5-tuple in tuser on tlast)
//   m_axis_result  = {match, ruleId} per packet, tlast && tvalid
interface KernelTopIfc;
	(* always_ready *)
	interface AxiStreamSlavePinsIfc#(512) s_axis_db;
	(* always_ready *)
	interface AxiStreamSlaveUserPinsIfc#(512, 128) s_axis_pkt;
	(* always_ready *)
	interface AxiStreamMasterPinsIfc#(32) m_axis_result;
endinterface
(* synthesize *)
(* default_reset="ap_rst_n", default_clock_osc="ap_clk" *)
module kernel (KernelTopIfc);
	Clock clk     <- exposeCurrentClock;
	Reset rstPipe <- mkSyncResetFromCR(2, clk);
	KernelMainIfc kernelMain <- mkKernelMain(reset_by rstPipe);

	interface s_axis_db     = kernelMain.s_axis_db;
	interface s_axis_pkt    = kernelMain.s_axis_pkt;
	interface m_axis_result = kernelMain.m_axis_result;
endmodule

endpackage
