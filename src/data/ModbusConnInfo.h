#pragma once

#include <stdint.h>

struct ModbusConnInfo {
	char    parity;
	int	    stopBits;
	int	    baseAddress;
	int	    dataBit;
	int	    tcpPort;
	int	    baudrate;
	int	    slaveAddr;
};
