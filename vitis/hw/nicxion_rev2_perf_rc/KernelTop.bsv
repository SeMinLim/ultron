package KernelTop;

import AxiStream::*;
import Clocks :: *;

import KernelMain::*;

interface KernelTopIfc;
    (* always_ready *)
    interface AxiStreamSlavePinsIfc#(512) s_axis_db;
    (* always_ready *)
    interface AxiStreamSlaveUserPinsIfc#(512, 128) s_axis_pkt;
    (* always_ready *)
    interface AxiStreamMasterPinsIfc#(32) m_axis_result;
endinterface
(* synthesize *)
// bsc G0046 x16 (reset lost at the AXI-stream methods) is expected: the
// methods are always_ready pin wrappers and the kernel is reset via rstPipe.
(* default_reset="ap_rst_n", default_clock_osc="ap_clk" *)
module kernel (KernelTopIfc);
    Clock clk     <- exposeCurrentClock;
    Reset rstPipe <- mkAsyncResetFromCR(2, clk);
    KernelMainIfc kernelMain <- mkKernelMain(reset_by rstPipe);

    interface s_axis_db     = kernelMain.s_axis_db;
    interface s_axis_pkt    = kernelMain.s_axis_pkt;
    interface m_axis_result = kernelMain.m_axis_result;
endmodule

endpackage
