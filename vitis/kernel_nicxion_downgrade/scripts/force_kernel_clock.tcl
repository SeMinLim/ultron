# Re-target the kernel clock (clock id 0) to a chosen frequency.
#
# WHY THIS EXISTS
# Vitis records the requested kernel frequency in two places and BOTH are
# ineffective on xilinx_u50_gen3x16_xdma_5_202210_1:
#
#   output/ulp_ooc_copy.xdc
#     create_clock -name USER_ulp_ucs/aclk_kernel_00 -period 4.0 \
#                  [get_ports ulp_ucs/aclk_kernel_00]
#     -> "WARNING: [Vivado 12-584] No ports matched 'ulp_ucs/aclk_kernel_00'".
#        The object name contains a slash, get_ports matches nothing, so the
#        constraint is a no-op.
#
#   output/_user_impl_clk.xdc
#     create_generated_clock -name clk_kernel_00_unbuffered_net \
#                            -divide_by 1 -multiply_by 1 -source <MMCM>/CLKIN1 <MMCM>/CLKOUT0
#     -> ties the kernel clock 1:1 to the MMCM input.  CLKIN1 is the 100 MHz
#        freerun reference, so the design is constrained at 10 ns no matter what
#        freqhz= or kernel_frequency= asked for.  Vivado logs
#        "A clock with name 'clk_kernel_00_unbuffered_net' already exists,
#         overwriting the previous clock", i.e. this one wins.
#
# Measured on 2026-09-22: requested 250 MHz, implemented at 10.000 ns / 100 MHz.
#
# HOW THIS FIXES IT
# Runs as STEPS.OPT_DESIGN.TCL.PRE, which executes after link_design and after
# every XDC has been read, so redefining the clock by the same name overrides
# both of the above (same mechanism Vitis itself relies on).
#
# 100 MHz CLKIN1 -> 250 MHz is x5 / 2.  Change MULT/DIV together if the target
# frequency changes; keep them integral so the ratio is exact.

set TARGET_MHZ 250
set MULT       5
set DIV        2

set mmcm level0_i/ulp/ulp_ucs/inst/aclk_kernel_00_hierarchy/clkwiz_aclk_kernel_00/inst/CLK_CORE_DRP_I/clk_inst/mmcme4_adv_inst
set src  $mmcm/CLKIN1
set dst  $mmcm/CLKOUT0

if {[llength [get_pins -quiet $dst]] == 0} {
    puts "WARNING \[force_kernel_clock\]: $dst not found; kernel clock left unchanged"
} elseif {[llength [get_pins -quiet $src]] == 0} {
    puts "WARNING \[force_kernel_clock\]: $src not found; kernel clock left unchanged"
} else {
    create_generated_clock -name clk_kernel_00_unbuffered_net \
        -source $src -multiply_by $MULT -divide_by $DIV $dst
    puts "INFO \[force_kernel_clock\]: kernel clock re-created at ${TARGET_MHZ} MHz (x${MULT}/${DIV} of CLKIN1)"
}
