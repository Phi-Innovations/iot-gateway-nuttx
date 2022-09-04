set(HEADER_FILES
	cdcacm.h
	data/Connection.h
	data/ModbusInfo.h
	data/ModbusConnInfo.h
	data/SlaveMap.h
	data/MqttInfo.h
	data/NetworkInfo.h
	data/ProductInfo.h
	data/SimCardInfo.h
	data/WiFiInfo.h
	data/Configuration.h
	data/ConfigData.h
	data/SlaveInfo.h
	data/TransmissionInfo.h
	data/CaptureInfo.h
	data/Status.h
	manager/Manager.h
	manager/commands/CommandIF.h
	manager/commands/ConfigCommand.h
	manager/commands/MqttCommand.h
	manager/commands/EthernetCommand.h
	manager/commands/WifiCommand.h
	manager/commands/GsmCommand.h
	manager/commands/ModbusCommand.h
	manager/commands/DatetimeCommand.h
	manager/commands/DeviceIdCommand.h
	manager/commands/OperationCommand.h
	manager/commands/ScanGeneralCommand.h
	manager/commands/ScanMapCommand.h
	manager/commands/CertCommand.h
	manager/commands/SystemCommand.h
	manager/commands/UpdateCommand.h
	manager/commands/StatusCommand.h
	manager/commands/ModbusReadCommand.h
	manager/commands/ModbusWriteCommand.h
	network/NetworkIF.h
	network/Ethernet.h
	network/Wifi.h
	defs.h
	Utils.h
	PhiGateway.h
	version.h
	Capture.h
	MqttClient.h
	Transmission.h
	Payload.h
	Leds.h
	Tls.h
	ModbusUtils.h
)

set(SOURCE_FILES
	data/Configuration.cpp
	data/SlaveMap.cpp
	data/ModbusRegister.cpp
	data/SystemData.cpp
	data/ConfigData.cpp
	manager/Manager.cpp
	manager/commands/ConfigCommand.cpp
	manager/commands/MqttCommand.cpp
	manager/commands/EthernetCommand.cpp
	manager/commands/WifiCommand.cpp
	manager/commands/GsmCommand.cpp
	manager/commands/ModbusCommand.cpp
	manager/commands/DatetimeCommand.cpp
	manager/commands/DeviceIdCommand.cpp
	manager/commands/OperationCommand.cpp
	manager/commands/ScanGeneralCommand.cpp
	manager/commands/ScanMapCommand.cpp
	manager/commands/CertCommand.cpp
	manager/commands/SystemCommand.cpp
	manager/commands/UpdateCommand.cpp
	manager/commands/StatusCommand.cpp
	manager/commands/ModbusReadCommand.cpp
	manager/commands/ModbusWriteCommand.cpp
	network/NetworkIF.cpp
	network/Ethernet.cpp
	network/Wifi.cpp
	PhiGateway.cpp
	Utils.cpp
	Capture.cpp
	MqttClient.cpp
	Transmission.cpp
	Payload.cpp
	Leds.cpp
	Tls.cpp
	ModbusUtils.cpp
)

link_directories(${EXE_NAME} ${NUTTX_PATH}/libs)

add_executable(${EXE_NAME} ${SOURCE_FILES} main.cpp ${HEADER_FILES})

if (NOT PARAM_SIM)
	add_custom_command(
		TARGET ${EXE_NAME}
		POST_BUILD
		COMMAND ${CMAKE_OBJCOPY} ARGS -S -O binary ${CMAKE_BINARY_DIR}/${EXE_NAME}.elf ${CMAKE_BINARY_DIR}/${EXE_NAME}.bin
	)
endif()

target_link_libraries(${EXE_NAME} mbedcrypto)
target_link_libraries(${EXE_NAME} mbedx509)
target_link_libraries(${EXE_NAME} mbedtls)
target_link_libraries(${EXE_NAME} mqttc)
target_link_libraries(${EXE_NAME} modbus)

target_link_libraries(${EXE_NAME} --start-group)

target_link_libraries(${EXE_NAME} sched)
target_link_libraries(${EXE_NAME} drivers)
target_link_libraries(${EXE_NAME} boards)
target_link_libraries(${EXE_NAME} c)
target_link_libraries(${EXE_NAME} mm)
target_link_libraries(${EXE_NAME} arch)
target_link_libraries(${EXE_NAME} xx)
target_link_libraries(${EXE_NAME} apps)
target_link_libraries(${EXE_NAME} fs)
target_link_libraries(${EXE_NAME} binfmt)
target_link_libraries(${EXE_NAME} board)
target_link_libraries(${EXE_NAME} gcc)
target_link_libraries(${EXE_NAME} supc++)
target_link_libraries(${EXE_NAME} net)

target_link_libraries(${EXE_NAME} --end-group)
