BUILD_DIR_BASE=build
DEBUG?=ON
SIM?=ON
BASE_PATH=$(PWD)

all:
	@echo "Targets:"
	@echo " default - builds for the board"
	@echo " default-sim - build for simulation environment"
	@echo " run     - builds and load on target"


clean:
	@rm -rf $(BUILD_DIR_BASE)*

.PHONY: default
default:
	cmake -S . -B $(BUILD_DIR_BASE) -G Ninja -DPARAM_DEBUG=$(DEBUG); \
	cmake --build $(BUILD_DIR_BASE)

.PHONY: default-sim
default-sim:
	cmake -S . -B $(BUILD_DIR_BASE) -G Ninja -DPARAM_DEBUG=$(DEBUG) \
		-DPARAM_SIM=$(SIM); \
	cmake --build $(BUILD_DIR_BASE)

release:
	cmake -S . -B $(BUILD_DIR_BASE) -G Ninja; \
	cmake --build $(BUILD_DIR_BASE)

run: default
	JLinkExe -commanderScript jlink/phigw.jlink

run-release: release
	JLinkExe -commanderScript jlink/phigw.jlink

erase:
	JLinkExe -commanderScript jlink/phigw-erase.jlink

load-bl:
	JLinkExe -commanderScript jlink/phigw-bl.jlink

update-arm:
	@rm -rf nuttx-export-10.0.1-arm
	@unzip ~/nuttx_ws/nuttx/nuttx-export-10.0.1.zip 
	@mv nuttx-export-10.0.1 nuttx-export-10.0.1-arm
	@cp -r ~/nuttx_ws/apps/include/netutils nuttx-export-10.0.1-arm/include/
	@cp -r ~/nuttx_ws/apps/include/fsutils nuttx-export-10.0.1-arm/include/
