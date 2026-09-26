# patch_clk_metadata.tcl
# Replace 2019.1-encrypted clk_metadata_adapter Verilog with a plain passthrough.
# The U50 202210_1 platform shell IP was encrypted with Xilinx Encryption Tool 2019.1;
# Vivado 2023+ cannot read that format.  The other_ipdefs copy in the XSA is plain
# text and functionally identical (assign clk_out = clk_in).
#
# Runs as STEPS.SYNTH_DESIGN.TCL.PRE on every synthesis run; pwd at that point
# is the run directory (.../prj.runs/<run_name>), so two levels up reaches .../prj
# which contains both prj.gen (ipshared copies) and the iprepo source files.

set passthrough {// clk_metadata_adapter passthrough (2019.1 encryption workaround)
module clk_metadata_adapter_v1_0_0(input clk_in, output clk_out);
  assign clk_out = clk_in;
endmodule}

# Search from two directory levels above CWD (.../prj.runs/<run> -> .../prj)
# and also from the VPL root (.../prj -> .../vpl) to cover the iprepo source.
set search_roots [list \
    [file dirname [file dirname [pwd]]] \
    [file dirname [file dirname [file dirname [pwd]]]] \
]

foreach search_root $search_roots {
    # catch handles non-zero find exit (e.g. permission denied on some subdir)
    catch {exec find $search_root -name "clk_metadata_adapter_v1_0_vl_rfs.v"} raw
    foreach f [split $raw "\n"] {
        if {$f eq ""} continue
        if {[catch {
            set fp [open $f r]; set data [read $fp]; close $fp
            if {[string match "*pragma protect*" $data]} {
                set fw [open $f w]
                puts $fw $passthrough
                close $fw
                puts "INFO \[patch_clk_metadata\]: replaced encrypted $f"
            }
        } err]} {
            puts "WARNING \[patch_clk_metadata\]: could not process $f : $err"
        }
    }
}
