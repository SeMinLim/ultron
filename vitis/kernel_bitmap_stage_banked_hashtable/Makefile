SHELL := /bin/bash
PWD = $(shell readlink -f .)

.DEFAULT_GOAL := help

NEEDS_TARGET := $(filter all run build,$(MAKECMDGOALS))
ifneq ($(NEEDS_TARGET),)
ifeq ($(filter $(TARGET),hw hw_emu),)
$(error [ERROR] TARGET must be specified! Usage: 'make $(word 1, $(NEEDS_TARGET)) TARGET=<hw_emu/hw>')
endif
endif

PLATFORM ?= xilinx_u50_gen3x16_xdma_5_202210_1
PROJECT := bitmap_stage_banked_hashtable

include makefile_us_alveo.mk
# kernel_ngram_filter and host_ngram_filter are symlinks inside bluevitis/ but live as
# siblings in their real location. CURDIR resolves to the physical path, so the shared
# ../../sw/host_$(PROJECT) path doesn't exist; override it here.
HOSTDIR := $(CURDIR)/../../sw/host_$(PROJECT)


help:
	@echo "Makefile Usage:"
	@echo "  make all TARGET=<hw_emu/hw> PLATFORM=<FPGA platform>"
	@echo "      Command to generate the design for specified Target and Shell."
	@echo ""
	@echo "  make run TARGET=<hw_emu/hw> PLATFORM=<FPGA platform>"
	@echo "      Command to run application in emulation."
	@echo ""
	@echo "  make build TARGET=<hw_emu/hw> PLATFORM=<FPGA platform>"
	@echo "      Command to build xclbin application."
	@echo ""
	@echo "  make host"
	@echo "      Command to build host application."
	@echo ""
	@echo "  make clean "
	@echo "      Command to remove the generated non-hardware files."
	@echo ""
	@echo "  make cleanall"
	@echo "      Command to remove all the generated files."
	@echo ""
