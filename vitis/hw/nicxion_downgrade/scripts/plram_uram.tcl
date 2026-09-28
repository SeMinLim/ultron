# Configure U50 PLRAM[0..1] to use UltraRAM.
#
# U50 Gen3x16 XDMA base_5 exposes PLRAM[0:1] on SLR0 and PLRAM[2:3] on SLR1.
# Platform address map limits each PLRAM bank to 128K (axi_bram_null_0 sits
# immediately above at +128K offset).
#   PLRAM[0] -> kernel_1.pkt    (packet blob, up to 128K)
#   PLRAM[1] -> kernel_1.result (result buffer, up to 128K)
#   HBM[0]   -> kernel_1.db    (DB blob, 353K+ — too large for PLRAM)

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

