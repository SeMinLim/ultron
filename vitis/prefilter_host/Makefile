.PHONY: all clean

XRT_DIR ?= $(XILINX_XRT)
ifeq ($(XRT_DIR),)
XRT_DIR := /opt/xilinx/xrt
endif

all:
	mkdir -p obj/
	g++ -g -std=c++17 -Wall -O0 main.cpp rule_loader.cpp -o ./obj/main -I$(XRT_DIR)/include/ -L$(XRT_DIR)/lib -lxrt_coreutil -pthread

clean:
	rm -rf obj
