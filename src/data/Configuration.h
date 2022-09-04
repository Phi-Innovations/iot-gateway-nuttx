#pragma once

#include <stdint.h>
#include <string>
#include <vector>

#include "ModbusConnInfo.h"
#include "NetworkInfo.h"
#include "MqttInfo.h"
#include "Connection.h"
#include "SimCardInfo.h"
#include "WiFiInfo.h"
#include "ProductInfo.h"

class Configuration {
private:
	int extractContent(char *data);
	
public:
	/* General operation parameters */
	int		logOutputMode;
	int		usedSimNb;
	int		cmdInterval;	/* Minutes */
	int		connectionMode;
	int		deviceId;
	int		modbusEnabled;
	int		transmissionMode;
	int		payloadType;
	int		scanInterval;	/* Minutes */
	int		sendInterval;	/* Minutes */
	int		operationMode;
	/* Connectivity parameters */
	ModbusConnInfo				modbus;
	NetworkInfo 				net;
	NetworkInfo 				net_wifi;
	MqttInfo 					mqtt;
	Connection 					updateFirmware;
	std::vector<SimCardInfo>	simcard;
	WifiInfo					wifi;
	/* Product specific parameters */
	ProductInfo 	prod;
	/* Analog and digital scan operation parameters */
	int		inputScanInterval;  /* Segundos */
	int		inputSendInterval; /* Minutos */
	int		inputEnabled;
	int		inputHasExpansion;
	/* Modbus operation parameters */
	int		modbusNbRetries;
	int		modbusDelayBetweenReads;
	/* Digital inputs pulse counter parameters */
	int		input1PulseCounterEnable;
	int		input1PulseCounterStart;  /* Rising / Falling */
	int		input2PulseCounterEnable;
	int		input2PulseCounterStart;  /* Rising / Falling */
	int		input1SendPulseEvent;
	int		input2SendPulseEvent;

	Configuration();
	~Configuration() { }
	void initializeDefaultValues(void);
	int createCertificate(void);
	int load(void);
	int save(void);
};
