
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
