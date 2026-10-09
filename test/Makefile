# Makefile
# See https://docs.cocotb.org/en/stable/quickstart.html for more info

# defaults
SIM ?= icarus
TOPLEVEL_LANG ?= verilog
SRC_DIR = $(PWD)/../src
PROJECT_SOURCES = project.v

ifneq ($(GATES),yes)

# RTL simulation:
SIM_BUILD				= sim_build/rtl
VERILOG_SOURCES += $(addprefix $(SRC_DIR)/,$(PROJECT_SOURCES))
COMPILE_ARGS 		+= -I$(SRC_DIR)

else

# Gate level simulation:
SIM_BUILD				= sim_build/gl
COMPILE_ARGS    += -DGL_TEST
COMPILE_ARGS    += -DFUNCTIONAL
COMPILE_ARGS    += -DUSE_POWER_PINS
COMPILE_ARGS    += -DSIM
COMPILE_ARGS    += -DUNIT_DELAY=\#1
VERILOG_SOURCES += $(PDK_ROOT)/sky130A/libs.ref/sky130_fd_sc_hd/verilog/primitives.v
VERILOG_SOURCES += $(PDK_ROOT)/sky130A/libs.ref/sky130_fd_sc_hd/verilog/sky130_fd_sc_hd.v

# this gets copied in by the GDS action workflow
VERILOG_SOURCES += $(PWD)/gate_level_netlist.v

endif

# Include the testbench sources:
VERILOG_SOURCES += $(PWD)/tb.v 
TOPLEVEL = tb

# MODULE is the basename of the Python test file
MODULE = test

# make BLOCK=yes: SHA-256 compression engine (sha07_block.v, test_sha07_block.py)
ifeq ($(BLOCK),yes)
VERILOG_SOURCES = $(SRC_DIR)/sha07_block.v $(SRC_DIR)/project.v
TOPLEVEL = sha07_block
MODULE = test_sha07_block
SIM_BUILD = sim_build/block
endif

# make HMAC=yes: HMAC controller (hmac07_ctrl.v, test_hmac_ctrl.py)
ifeq ($(HMAC),yes)
VERILOG_SOURCES = $(SRC_DIR)/hmac07_ctrl.v $(SRC_DIR)/sha07_block.v $(SRC_DIR)/project.v
TOPLEVEL = hmac07_ctrl
MODULE = test_hmac_ctrl
SIM_BUILD = sim_build/hmac
endif

# make AVMM=yes: Avalon-MM wrapper (hmac07_avmm.v, test_hmac_avmm.py)
ifeq ($(AVMM),yes)
VERILOG_SOURCES = $(SRC_DIR)/hmac07_avmm.v $(SRC_DIR)/hmac07_ctrl.v $(SRC_DIR)/sha07_block.v $(SRC_DIR)/project.v
TOPLEVEL = hmac07_avmm
MODULE = test_hmac_avmm
SIM_BUILD = sim_build/avmm
endif

# include cocotb's make rules to take care of the simulator setup
include $(shell cocotb-config --makefiles)/Makefile.sim
