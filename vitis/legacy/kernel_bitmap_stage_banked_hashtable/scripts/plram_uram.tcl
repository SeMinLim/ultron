# Configure U50 PLRAM[0..1] to use UltraRAM.
#
# U50 Gen3x16 XDMA base_5 exposes PLRAM[0:1] on SLR0 and PLRAM[2:3] on SLR1.
# Platform address map limits each PLRAM bank to 128K (axi_bram_null_0 sits
# immediately above at +128K offset).
#   PLRAM[0] -> kernel_1.pkt    (packet blob, up to 128K)
#   PLRAM[1] -> kernel_1.result (result buffer, up to 128K)
#   HBM[0]   -> kernel_1.db    (DB blob, 353K+ — too large for PLRAM)

# ---------------------------------------------------------------------------
# Patch 2019.1-encrypted clk_metadata_adapter source before synthesis runs
# copy it to ipshared.  Directly overwrite the encrypted HDL in ii_infra_ipdefs
# with the plain-text copy from ~/clk_metadata_adapter.  pwd here is .../vpl.
# We do NOT touch ip_repo_paths or update_ip_catalog to avoid locking BDs.
# ---------------------------------------------------------------------------
set _plain_src /home/seclab/clk_metadata_adapter/clk_metadata_adapter_v1_0/hdl/clk_metadata_adapter_v1_0_vl_rfs.v
set _enc_dst [file join [pwd] .local/hw_platform/iprepo/ipdefs/ii_infra_ipdefs/clk_metadata_adapter_v1_0/hdl/clk_metadata_adapter_v1_0_vl_rfs.v]
if {[file exists $_enc_dst]} {
    set _fp [open $_enc_dst r]; set _chk [read $_fp]; close $_fp
    if {[string match "*pragma protect*" $_chk]} {
        file copy -force $_plain_src $_enc_dst
        puts "INFO \[patch_clk_metadata\]: replaced encrypted $_enc_dst"
    } else {
        puts "INFO \[patch_clk_metadata\]: $_enc_dst already plain-text, skipping"
    }
} else {
    puts "WARNING \[patch_clk_metadata\]: encrypted target not found: $_enc_dst"
}
unset -nocomplain _plain_src _enc_dst _fp _chk

set mem_subsys [get_bd_cells /memory_subsystem]

sdx_memory_subsystem::update_plram_specification \
  $mem_subsys PLRAM_MEM00 { \
    SIZE 128K \
    AXI_DATA_WIDTH 512 \
    SLR_ASSIGNMENT SLR0 \
    READ_LATENCY 1 \
    MEMORY_PRIMITIVE URAM \
  }

sdx_memory_subsystem::update_plram_specification \
  $mem_subsys PLRAM_MEM01 { \
    SIZE 128K \
    AXI_DATA_WIDTH 512 \
    SLR_ASSIGNMENT SLR0 \
    READ_LATENCY 1 \
    MEMORY_PRIMITIVE URAM \
  }

validate_bd_design -force
save_bd_design

