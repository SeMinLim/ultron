SHELL := /bin/bash

BUILD_DIR := ./$(TARGET)
OBJ_DIR := ./obj
HOSTDIR := ../host_$(PROJECT)
BLIB_DIR := ../../../bluelibrary
PLRAM_URAM_TCL := ./scripts/plram_uram.tcl

CXXFLAGS := -g -std=c++17 -Wall -O2

VIVADO := $(XILINX_VIVADO)/bin/vivado
BSCFLAGS := -show-schedule -aggressive-conditions 
BSCFLAGS_SYNTH := -bdir $(OBJ_DIR) -vdir $(OBJ_DIR)/verilog -simdir $(OBJ_DIR) -info-dir $(OBJ_DIR) -fdir $(OBJ_DIR) 
JOBS := 8
KERNEL_CLK_TCL := $(CURDIR)/scripts/force_kernel_clock.tcl
VPPFLAGS := --vivado.param general.maxThreads=$(JOBS) --vivado.impl.jobs $(JOBS) --vivado.synth.jobs $(JOBS) --temp_dir $(BUILD_DIR) --log_dir $(BUILD_DIR) --report_dir $(BUILD_DIR) --report_level 2 --advanced.param compiler.userPreSysLinkOverlayTcl=$(PLRAM_URAM_TCL) --vivado.prop run.impl_1.STEPS.OPT_DESIGN.TCL.PRE=$(KERNEL_CLK_TCL)

.PHONY: all run build host clean cleanall emconfig package
all: package
build: $(BUILD_DIR)/kernel.xclbin

host:
	$(MAKE) -C $(HOSTDIR) CXXFLAGS="$(CXXFLAGS)"

$(OBJ_DIR)/verilog/.done: $(wildcard *.bsv) $(wildcard *.v) ./scripts/force_block_ram.sh
	mkdir -p $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)/verilog
	bsc $(BSCFLAGS) $(BSCFLAGS_SYNTH) -remove-dollar -p +:$(BLIB_DIR)/bsv -verilog -u -g kernel KernelTop.bsv
	cd $(OBJ_DIR)/verilog/ && bash ../../scripts/verilogcopy.sh
	cp *.v $(OBJ_DIR)/verilog/
	cp $(BLIB_DIR)/verilog/*.v $(OBJ_DIR)/verilog/
	bash ./scripts/force_block_ram.sh
	@touch $@
$(BUILD_DIR)/kernel.xo: ./kernel.xml ./scripts/package_kernel.tcl ./scripts/gen_xo.tcl $(OBJ_DIR)/verilog/.done
	mkdir -p $(BUILD_DIR)
	$(VIVADO) -mode batch -tempDir $(OBJ_DIR) -source scripts/gen_xo.tcl -tclargs $@ kernel $(TARGET) $(PLATFORM)
HLS_DIR := ./hls
$(BUILD_DIR)/mm2s_db.xo: $(HLS_DIR)/mm2s_db.cpp
	mkdir -p $(BUILD_DIR)
	v++ -c -t $(TARGET) --platform $(PLATFORM) -k mm2s_db -o $@ $<
$(BUILD_DIR)/s2mm.xo: $(HLS_DIR)/s2mm.cpp
	mkdir -p $(BUILD_DIR)
	v++ -c -t $(TARGET) --platform $(PLATFORM) -k s2mm -o $@ $<
$(BUILD_DIR)/mm2s_pkt.xo: $(HLS_DIR)/mm2s_pkt.cpp
	mkdir -p $(BUILD_DIR)
	v++ -c -t $(TARGET) --platform $(PLATFORM) -k mm2s_pkt -o $@ $<
$(BUILD_DIR)/kernel.xclbin: $(BUILD_DIR)/kernel.xo $(BUILD_DIR)/mm2s_db.xo $(BUILD_DIR)/mm2s_pkt.xo $(BUILD_DIR)/s2mm.xo
	mkdir -p $(BUILD_DIR)
	v++ -l -t $(TARGET) --platform $(PLATFORM) --config $(if $(filter hw_emu,$(TARGET)),u50_emu.cfg,u50.cfg) $(VPPFLAGS) \
	    $(BUILD_DIR)/kernel.xo $(BUILD_DIR)/mm2s_db.xo $(BUILD_DIR)/mm2s_pkt.xo $(BUILD_DIR)/s2mm.xo -o $@
	@if [ "$(TARGET)" = "hw" ]; then \
		vivado -mode batch -source ./scripts/report_hierarchical_utilization.tcl -tclargs $(BUILD_DIR); \
	fi
emconfig: $(BUILD_DIR)/emconfig.json
$(BUILD_DIR)/emconfig.json:
	mkdir -p $(BUILD_DIR)
	emconfigutil --platform $(PLATFORM) --od $(BUILD_DIR) --nd 1
package: host build emconfig
	mkdir -p $(BUILD_DIR)/hw_package
	cp $(HOSTDIR)/obj/main $(BUILD_DIR)/hw_package/
	cp $(BUILD_DIR)/kernel.xclbin $(BUILD_DIR)/hw_package/
	cp $(BUILD_DIR)/emconfig.json $(BUILD_DIR)/hw_package/
	cp xrt.ini $(BUILD_DIR)/hw_package/
	cd $(BUILD_DIR) && tar czvf hw_package.tgz hw_package/
XCLBIN_ABS_PATH := $(CURDIR)/$(BUILD_DIR)/kernel.xclbin
DB_BLOB  ?= $(HOSTDIR)/db.bin
PCAP     ?= $(HOSTDIR)/full.pcap
RULE     ?= $(HOSTDIR)/rule.txt
RULE_STAMP := $(HOSTDIR)/.db_rule.stamp

# Rebuild $(DB_BLOB) whenever $(RULE) *path* changes (not just contents),
# so `make run RULE=.../rule16k.txt` after `make run RULE=.../rule.txt`
# regenerates the DB instead of reusing the stale one.
.PHONY: FORCE
FORCE:
$(RULE_STAMP): FORCE
	@if [ ! -f $@ ] || [ "$$(cat $@)" != "$(RULE)" ]; then \
		echo "$(RULE)" > $@; \
	fi

$(DB_BLOB): $(HOSTDIR)/gen/ngram_db_gen.c $(HOSTDIR)/gen/rule_loader.c $(HOSTDIR)/gen/singleton.c $(HOSTDIR)/gen/bitmap.c $(RULE) $(RULE_STAMP)
	$(MAKE) -C $(HOSTDIR)/gen ngram_db_gen
	$(HOSTDIR)/gen/ngram_db_gen $(RULE) $(DB_BLOB)

run: $(DB_BLOB)
ifeq ($(TARGET),hw_emu)
	@echo "========================================="
	@echo " Running Hardware Emulation... "
	@echo "========================================="
	cp -rf $(BUILD_DIR)/emconfig.json $(HOSTDIR)/
	cd $(HOSTDIR) && export XCL_EMULATION_MODE=hw_emu && ./obj/main $(XCLBIN_ABS_PATH) $(DB_BLOB) $(PCAP)
else
	@echo "========================================="
	@echo " Running on Actual Hardware... "
	@echo "========================================="
	cd $(HOSTDIR) && unset XCL_EMULATION_MODE && ./obj/main $(XCLBIN_ABS_PATH) $(DB_BLOB) $(PCAP)
endif
clean:
	@echo "Cleaning non-hardware files (Logs, Objects)..."
	rm -rf $(OBJ_DIR) *.log *.jou xilinx* .Xil _x emconfig.json
	rm -rf ./analyzer_input
	rm -rf *.csv xrt.run_summary
	$(MAKE) -C $(HOSTDIR) clean

cleanall: clean
	@echo "Cleaning ALL generated files (including heavy bitstreams)..."
	rm -rf ./hw ./hw_emu .ipcache
