#include "ConfigData.h"

#include <syslog.h>
#include <netutils/cJSON.h>

std::string ConfigData::buildConfigFileContent(Configuration *cfg) {

	cJSON *root = cJSON_CreateObject();

	cJSON_AddNumberToObject(root,"logOutputMode",cfg->logOutputMode);
	cJSON_AddNumberToObject(root,"usedSimNb",cfg->usedSimNb);
	cJSON_AddNumberToObject(root,"cmdInterval",cfg->cmdInterval);
	cJSON_AddNumberToObject(root,"connectionMode",cfg->connectionMode);
	cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
	cJSON_AddNumberToObject(root,"modbusEnabled",cfg->modbusEnabled);
	cJSON_AddNumberToObject(root,"transmissionMode",cfg->transmissionMode);
	cJSON_AddNumberToObject(root,"payloadType",cfg->payloadType);
	/* Data is saved in minutes, but used internally in seconds */
	cJSON_AddNumberToObject(root,"scanInterval",cfg->scanInterval / 60);
	/* Data is saved in minutes, but used internally in seconds */
	cJSON_AddNumberToObject(root,"sendInterval",cfg->sendInterval / 60);
	cJSON_AddNumberToObject(root,"operationMode",cfg->operationMode);

	cJSON_AddNumberToObject(root,"inputScanInterval",cfg->inputScanInterval);
	cJSON_AddNumberToObject(root,"inputSendInterval",cfg->inputSendInterval);
	cJSON_AddNumberToObject(root,"inputEnabled",cfg->inputEnabled);
	cJSON_AddNumberToObject(root,"inputHasExpansion",cfg->inputHasExpansion);
	cJSON_AddNumberToObject(root,"modbusNbRetries",cfg->modbusNbRetries);
	cJSON_AddNumberToObject(root,"modbusDelayBetweenReads",cfg->modbusDelayBetweenReads);
	cJSON_AddNumberToObject(root,"input1PulseCounterEnable",cfg->input1PulseCounterEnable);
	cJSON_AddNumberToObject(root,"input1PulseCounterStart",cfg->input1PulseCounterStart);
	cJSON_AddNumberToObject(root,"input2PulseCounterEnable",cfg->input2PulseCounterEnable);
	cJSON_AddNumberToObject(root,"input2PulseCounterStart",cfg->input2PulseCounterStart);
	cJSON_AddNumberToObject(root,"input1SendPulseEvent",cfg->input1SendPulseEvent);
	cJSON_AddNumberToObject(root,"input2SendPulseEvent",cfg->input2SendPulseEvent);

	cJSON *jModbus = cJSON_CreateObject();
	char strParity[2];
	memset(strParity,0,sizeof(strParity));
	strParity[0] = cfg->modbus.parity;
	cJSON_AddStringToObject(jModbus,"parity",strParity);
	cJSON_AddNumberToObject(jModbus,"stopBits",cfg->modbus.stopBits);
	cJSON_AddNumberToObject(jModbus,"baseAddress",cfg->modbus.baseAddress);
	cJSON_AddNumberToObject(jModbus,"dataBit",cfg->modbus.dataBit);
	cJSON_AddNumberToObject(jModbus,"tcpPort",cfg->modbus.tcpPort);
	cJSON_AddNumberToObject(jModbus,"baudrate",cfg->modbus.baudrate);
	cJSON_AddNumberToObject(jModbus,"slaveAddr",cfg->modbus.slaveAddr);
	cJSON_AddItemToObject(root,"modbus",jModbus);

	cJSON *jNet = cJSON_CreateObject();
	cJSON_AddStringToObject(jNet,"ipAddr",cfg->net.ipAddr.c_str());
	cJSON_AddStringToObject(jNet,"netmask",cfg->net.netmask.c_str());
	cJSON_AddStringToObject(jNet,"gateway",cfg->net.gateway.c_str());
	cJSON_AddStringToObject(jNet,"dns",cfg->net.dns.c_str());
	cJSON_AddStringToObject(jNet,"macAddress",cfg->net.macAddress.c_str());
	cJSON_AddNumberToObject(jNet,"isDHCP",cfg->net.isDHCP);
	cJSON_AddItemToObject(root,"net",jNet);

	cJSON *jNetWifi = cJSON_CreateObject();
	cJSON_AddStringToObject(jNetWifi,"ipAddr",cfg->net_wifi.ipAddr.c_str());
	cJSON_AddStringToObject(jNetWifi,"netmask",cfg->net_wifi.netmask.c_str());
	cJSON_AddStringToObject(jNetWifi,"gateway",cfg->net_wifi.gateway.c_str());
	cJSON_AddStringToObject(jNetWifi,"dns",cfg->net_wifi.dns.c_str());
	cJSON_AddStringToObject(jNetWifi,"macAddress",cfg->net_wifi.macAddress.c_str());
	cJSON_AddNumberToObject(jNetWifi,"isDHCP",cfg->net_wifi.isDHCP);
	cJSON_AddItemToObject(root,"net_wifi",jNetWifi);

	cJSON *jMqtt = cJSON_CreateObject();
	cJSON_AddNumberToObject(jMqtt,"useTls",cfg->mqtt.useTls);
	cJSON_AddNumberToObject(jMqtt,"tlsAuthMode",cfg->mqtt.tlsAuthMode);
	cJSON_AddNumberToObject(jMqtt,"cmdCallInterval",cfg->mqtt.cmdCallInterval);
	cJSON *jMqttServer = cJSON_CreateObject();
	cJSON_AddNumberToObject(jMqttServer,"port",cfg->mqtt.server.port);
	cJSON_AddStringToObject(jMqttServer,"address",cfg->mqtt.server.address.c_str());
	cJSON_AddItemToObject(jMqtt,"server",jMqttServer);
	cJSON_AddStringToObject(jMqtt,"cliendId",cfg->mqtt.cliendId.c_str());
	cJSON_AddStringToObject(jMqtt,"pubTopic",cfg->mqtt.pubTopic.c_str());
	cJSON_AddStringToObject(jMqtt,"cmdTopic",cfg->mqtt.cmdTopic.c_str());
	cJSON_AddStringToObject(jMqtt,"rspTopic",cfg->mqtt.rspTopic.c_str());
	cJSON_AddStringToObject(jMqtt,"lwTopic",cfg->mqtt.lwTopic.c_str());
	cJSON_AddStringToObject(jMqtt,"username",cfg->mqtt.username.c_str());
	cJSON_AddStringToObject(jMqtt,"password",cfg->mqtt.password.c_str());
	cJSON_AddItemToObject(root,"mqtt",jMqtt);

	cJSON *jUpdateFirmware = cJSON_CreateObject();
	cJSON_AddNumberToObject(jUpdateFirmware,"port",cfg->updateFirmware.port);
	cJSON_AddStringToObject(jUpdateFirmware,"address",cfg->updateFirmware.address.c_str());
	cJSON_AddItemToObject(root,"updateFirmware",jUpdateFirmware);
	
	cJSON *jSimCard = cJSON_CreateArray();
    for (size_t i=0;i<cfg->simcard.size();i++) {
		cJSON *jSimCardItem = cJSON_CreateObject();
		cJSON_AddStringToObject(jSimCardItem,"apn",cfg->simcard[i].apn.c_str());
		cJSON_AddStringToObject(jSimCardItem,"user",cfg->simcard[i].user.c_str());
		cJSON_AddStringToObject(jSimCardItem,"pwd",cfg->simcard[i].pwd.c_str());
		cJSON_AddNumberToObject(jSimCardItem,"connId",cfg->simcard[i].connId);
		cJSON_AddNumberToObject(jSimCardItem,"direct_mode",cfg->simcard[i].direct_mode);
		cJSON_AddItemToArray(jSimCard, jSimCardItem);
    }
	cJSON_AddItemToObject(root,"simcard",jSimCard);

	cJSON *jWifi = cJSON_CreateObject();
	cJSON_AddStringToObject(jWifi,"ssid",cfg->wifi.ssid.c_str());
	cJSON_AddStringToObject(jWifi,"password",cfg->wifi.passwd.c_str());
	cJSON_AddItemToObject(root,"wifi",jWifi);

	cJSON *jProd = cJSON_CreateObject();
	cJSON_AddStringToObject(jProd,"serialNumber",cfg->prod.serialNumber.c_str());
	cJSON_AddItemToObject(root,"prod",jProd);

	char *out = cJSON_PrintUnformatted(root);
	std::string output(out,strlen(out));

	cJSON_Delete(root);
	free(out);

	return output;
}

int ConfigData::extractConfigFileContent(const char *data, Configuration *cfg) {
	/*
	 * Parsing the file content
	 */
	cJSON *jData = cJSON_Parse(data);
	if (jData == NULL) {
		syslog(LOG_ERR, "Problem parsing configuration file\n");
		return -1;
	}
	/*
	 * Extracting information
	 */
	const cJSON* logOutputMode = cJSON_GetObjectItemCaseSensitive(jData,"logOutputMode");
	if (cJSON_IsNumber(logOutputMode)) {
		cfg->logOutputMode = logOutputMode->valueint;
	}
	const cJSON* usedSimNb = cJSON_GetObjectItemCaseSensitive(jData,"usedSimNb");
	if (cJSON_IsNumber(usedSimNb)) {
		cfg->usedSimNb = usedSimNb->valueint;
	}
	const cJSON* cmdInterval = cJSON_GetObjectItemCaseSensitive(jData,"cmdInterval");
	if (cJSON_IsNumber(cmdInterval)) {
		cfg->cmdInterval = cmdInterval->valueint;
	}
	const cJSON* connectionMode = cJSON_GetObjectItemCaseSensitive(jData,"connectionMode");
	if (cJSON_IsNumber(connectionMode)) {
		cfg->connectionMode = connectionMode->valueint;
	}
	const cJSON* deviceId = cJSON_GetObjectItemCaseSensitive(jData,"deviceId");
	if (cJSON_IsNumber(deviceId)) {
		cfg->deviceId = deviceId->valueint;
	}
	const cJSON* modbusEnabled = cJSON_GetObjectItemCaseSensitive(jData,"modbusEnabled");
	if (cJSON_IsNumber(modbusEnabled)) {
		cfg->modbusEnabled = modbusEnabled->valueint;
	}
	const cJSON* independentMode = cJSON_GetObjectItemCaseSensitive(jData,"transmissionMode");
	if (cJSON_IsNumber(independentMode)) {
		cfg->transmissionMode = independentMode->valueint;
	}
	const cJSON* payloadType = cJSON_GetObjectItemCaseSensitive(jData,"payloadType");
	if (cJSON_IsNumber(payloadType)) {
		cfg->payloadType = payloadType->valueint;
	}
	const cJSON* scanInterval = cJSON_GetObjectItemCaseSensitive(jData,"scanInterval");
	if (cJSON_IsNumber(scanInterval)) {
		/* Data is saved in minutes, but used internally in seconds */
		cfg->scanInterval = scanInterval->valueint * 60;
	}
	const cJSON* sendInterval = cJSON_GetObjectItemCaseSensitive(jData,"sendInterval");
	if (cJSON_IsNumber(sendInterval)) {
		/* Data is saved in minutes, but used internally in seconds */
		cfg->sendInterval = sendInterval->valueint * 60;
	}
	const cJSON* operationMode = cJSON_GetObjectItemCaseSensitive(jData,"operationMode");
	if (cJSON_IsNumber(operationMode)) {
		cfg->operationMode = operationMode->valueint;
	}
	const cJSON* inputScanInterval = cJSON_GetObjectItemCaseSensitive(jData,"inputScanInterval");
	if (cJSON_IsNumber(inputScanInterval)) {
		cfg->inputScanInterval = inputScanInterval->valueint;
	}
	const cJSON* inputSendInterval = cJSON_GetObjectItemCaseSensitive(jData,"inputSendInterval");
	if (cJSON_IsNumber(inputSendInterval)) {
		cfg->inputSendInterval = inputSendInterval->valueint;
	}
	const cJSON* inputEnabled = cJSON_GetObjectItemCaseSensitive(jData,"inputEnabled");
	if (cJSON_IsNumber(inputEnabled)) {
		cfg->inputEnabled = inputEnabled->valueint;
	}
	const cJSON* inputHasExpansion = cJSON_GetObjectItemCaseSensitive(jData,"inputHasExpansion");
	if (cJSON_IsNumber(inputHasExpansion)) {
		cfg->inputHasExpansion = inputHasExpansion->valueint;
	}
	const cJSON* modbusNbRetries = cJSON_GetObjectItemCaseSensitive(jData,"modbusNbRetries");
	if (cJSON_IsNumber(modbusNbRetries)) {
		cfg->modbusNbRetries = modbusNbRetries->valueint;
	}
	const cJSON* modbusDelayBetweenReads = cJSON_GetObjectItemCaseSensitive(jData,"modbusDelayBetweenReads");
	if (cJSON_IsNumber(modbusDelayBetweenReads)) {
		cfg->modbusDelayBetweenReads = modbusDelayBetweenReads->valueint;
	}
	const cJSON* input1PulseCounterEnable = cJSON_GetObjectItemCaseSensitive(jData,"input1PulseCounterEnable");
	if (cJSON_IsNumber(input1PulseCounterEnable)) {
		cfg->input1PulseCounterEnable = input1PulseCounterEnable->valueint;
	}
	const cJSON* input1PulseCounterStart = cJSON_GetObjectItemCaseSensitive(jData,"input1PulseCounterStart");
	if (cJSON_IsNumber(input1PulseCounterStart)) {
		cfg->input1PulseCounterStart = input1PulseCounterStart->valueint;
	}
	const cJSON* input2PulseCounterEnable = cJSON_GetObjectItemCaseSensitive(jData,"input2PulseCounterEnable");
	if (cJSON_IsNumber(input2PulseCounterEnable)) {
		cfg->input2PulseCounterEnable = input2PulseCounterEnable->valueint;
	}
	const cJSON* input2PulseCounterStart = cJSON_GetObjectItemCaseSensitive(jData,"input2PulseCounterStart");
	if (cJSON_IsNumber(input2PulseCounterStart)) {
		cfg->input2PulseCounterStart = input2PulseCounterStart->valueint;
	}
	const cJSON* input1SendPulseEvent = cJSON_GetObjectItemCaseSensitive(jData,"input1SendPulseEvent");
	if (cJSON_IsNumber(input1SendPulseEvent)) {
		cfg->input1SendPulseEvent = input1SendPulseEvent->valueint;
	}
	const cJSON* input2SendPulseEvent = cJSON_GetObjectItemCaseSensitive(jData,"input2SendPulseEvent");
	if (cJSON_IsNumber(input2SendPulseEvent)) {
		cfg->input2SendPulseEvent = input2SendPulseEvent->valueint;
	}
	const cJSON* modbus = cJSON_GetObjectItemCaseSensitive(jData,"modbus");
	if (cJSON_IsObject(modbus)) {
		const cJSON* parity = cJSON_GetObjectItemCaseSensitive(modbus,"parity");
		if (cJSON_IsString(parity)) {
			cfg->modbus.parity = parity->valuestring[0];
		}
		else {
			cfg->modbus.parity = 'N';
		}
		const cJSON* stopBits = cJSON_GetObjectItemCaseSensitive(modbus,"stopBits");
		if (cJSON_IsNumber(stopBits)) {
			cfg->modbus.stopBits = stopBits->valueint;
		}
		else {
			cfg->modbus.stopBits = 8;
		}
		const cJSON* baseAddress = cJSON_GetObjectItemCaseSensitive(modbus,"baseAddress");
		if (cJSON_IsNumber(baseAddress)) {
			cfg->modbus.baseAddress = baseAddress->valueint;
		}
		else {
			cfg->modbus.baseAddress = 0;
		}
		const cJSON* dataBit = cJSON_GetObjectItemCaseSensitive(modbus,"dataBit");
		if (cJSON_IsNumber(dataBit)) {
			cfg->modbus.dataBit = dataBit->valueint;
		}
		else {
			cfg->modbus.dataBit = 1;
		}
		const cJSON* tcpPort = cJSON_GetObjectItemCaseSensitive(modbus,"tcpPort");
		if (cJSON_IsNumber(tcpPort)) {
			cfg->modbus.tcpPort = tcpPort->valueint;
		}
		else {
			cfg->modbus.tcpPort = 1502;
		}
		const cJSON* baudrate = cJSON_GetObjectItemCaseSensitive(modbus,"baudrate");
		if (cJSON_IsNumber(baudrate)) {
			cfg->modbus.baudrate = baudrate->valueint;
		}
		else {
			cfg->modbus.baudrate = 38400;
		}
		const cJSON* slaveAddr = cJSON_GetObjectItemCaseSensitive(modbus,"slaveAddr");
		if (cJSON_IsNumber(slaveAddr)) {
			cfg->modbus.slaveAddr = slaveAddr->valueint;
		}
		else {
			cfg->modbus.slaveAddr = 1;
		}
	}

	const cJSON* net = cJSON_GetObjectItemCaseSensitive(jData,"net");
	if (cJSON_IsObject(net)) {
		const cJSON* isDHCP = cJSON_GetObjectItemCaseSensitive(net,"isDHCP");
		if (cJSON_IsNumber(isDHCP)) {
			cfg->net.isDHCP = isDHCP->valueint;
		}
		const cJSON* ipAddr = cJSON_GetObjectItemCaseSensitive(net,"ipAddr");
		if (cJSON_IsString(ipAddr)) {
			cfg->net.ipAddr = ipAddr->valuestring;
		}
		const cJSON* netmask = cJSON_GetObjectItemCaseSensitive(net,"netmask");
		if (cJSON_IsString(netmask)) {
			cfg->net.netmask = netmask->valuestring;
		}
		const cJSON* gateway = cJSON_GetObjectItemCaseSensitive(net,"gateway");
		if (cJSON_IsString(gateway)) {
			cfg->net.gateway = gateway->valuestring;
		}
		const cJSON* dns = cJSON_GetObjectItemCaseSensitive(net,"dns");
		if (cJSON_IsString(dns)) {
			cfg->net.dns = dns->valuestring;
		}
		const cJSON* macAddress = cJSON_GetObjectItemCaseSensitive(net,"macAddress");
		if (cJSON_IsString(macAddress)) {
			cfg->net.macAddress = macAddress->valuestring;
		}
	}

	const cJSON* net_wifi = cJSON_GetObjectItemCaseSensitive(jData,"net_wifi");
	if (cJSON_IsObject(net_wifi)) {
		const cJSON* isDHCP = cJSON_GetObjectItemCaseSensitive(net_wifi,"isDHCP");
		if (cJSON_IsNumber(isDHCP)) {
			cfg->net_wifi.isDHCP = isDHCP->valueint;
		}
		const cJSON* ipAddr = cJSON_GetObjectItemCaseSensitive(net_wifi,"ipAddr");
		if (cJSON_IsString(ipAddr)) {
			cfg->net_wifi.ipAddr = ipAddr->valuestring;
		}
		const cJSON* netmask = cJSON_GetObjectItemCaseSensitive(net_wifi,"netmask");
		if (cJSON_IsString(netmask)) {
			cfg->net_wifi.netmask = netmask->valuestring;
		}
		const cJSON* gateway = cJSON_GetObjectItemCaseSensitive(net_wifi,"gateway");
		if (cJSON_IsString(gateway)) {
			cfg->net_wifi.gateway = gateway->valuestring;
		}
		const cJSON* dns = cJSON_GetObjectItemCaseSensitive(net_wifi,"dns");
		if (cJSON_IsString(dns)) {
			cfg->net_wifi.dns = dns->valuestring;
		}
		const cJSON* macAddress = cJSON_GetObjectItemCaseSensitive(net_wifi,"macAddress");
		if (cJSON_IsString(macAddress)) {
			cfg->net_wifi.macAddress = macAddress->valuestring;
		}
	}

	const cJSON* mqtt = cJSON_GetObjectItemCaseSensitive(jData,"mqtt");
	if (cJSON_IsObject(mqtt)) {
		const cJSON* useTls = cJSON_GetObjectItemCaseSensitive(mqtt,"useTls");
		if (cJSON_IsNumber(useTls)) {
			cfg->mqtt.useTls = useTls->valueint;
		}
		const cJSON* tlsAuthMode = cJSON_GetObjectItemCaseSensitive(mqtt,"tlsAuthMode");
		if (cJSON_IsNumber(tlsAuthMode)) {
			cfg->mqtt.tlsAuthMode = tlsAuthMode->valueint;
		}
		const cJSON* cmdCallInterval = cJSON_GetObjectItemCaseSensitive(mqtt,"cmdCallInterval");
		if (cJSON_IsNumber(cmdCallInterval)) {
			cfg->mqtt.cmdCallInterval = cmdCallInterval->valueint;
		}
		const cJSON* cliendId = cJSON_GetObjectItemCaseSensitive(mqtt,"cliendId");
		if (cJSON_IsString(cliendId)) {
			cfg->mqtt.cliendId = cliendId->valuestring;
		}
		const cJSON* pubTopic = cJSON_GetObjectItemCaseSensitive(mqtt,"pubTopic");
		if (cJSON_IsString(pubTopic)) {
			cfg->mqtt.pubTopic = pubTopic->valuestring;
		}
		const cJSON* cmdTopic = cJSON_GetObjectItemCaseSensitive(mqtt,"cmdTopic");
		if (cJSON_IsString(cmdTopic)) {
			cfg->mqtt.cmdTopic = cmdTopic->valuestring;
		}
		const cJSON* rspTopic = cJSON_GetObjectItemCaseSensitive(mqtt,"rspTopic");
		if (cJSON_IsString(rspTopic)) {
			cfg->mqtt.rspTopic = rspTopic->valuestring;
		}
		const cJSON* lwTopic = cJSON_GetObjectItemCaseSensitive(mqtt,"lwTopic");
		if (cJSON_IsString(lwTopic)) {
			cfg->mqtt.lwTopic = lwTopic->valuestring;
		}
		const cJSON* username = cJSON_GetObjectItemCaseSensitive(mqtt,"username");
		if (cJSON_IsString(username)) {
			cfg->mqtt.username = username->valuestring;
		}
		const cJSON* password = cJSON_GetObjectItemCaseSensitive(mqtt,"password");
		if (cJSON_IsString(password)) {
			cfg->mqtt.password = password->valuestring;
		}
		const cJSON* server = cJSON_GetObjectItemCaseSensitive(mqtt,"server");
		if (cJSON_IsObject(server)) {
			const cJSON* port = cJSON_GetObjectItemCaseSensitive(server,"port");
			if (cJSON_IsNumber(port)) {
				cfg->mqtt.server.port = port->valueint;
			}
			const cJSON* address = cJSON_GetObjectItemCaseSensitive(server,"address");
			if (cJSON_IsString(address)) {
				cfg->mqtt.server.address = address->valuestring;
			}
		}
	}

	const cJSON* updateFirmware = cJSON_GetObjectItemCaseSensitive(jData,"updateFirmware");
	if (cJSON_IsObject(updateFirmware)) {
		const cJSON* port = cJSON_GetObjectItemCaseSensitive(updateFirmware,"port");
		if (cJSON_IsNumber(port)) {
			cfg->updateFirmware.port = port->valueint;
		}
		const cJSON* address = cJSON_GetObjectItemCaseSensitive(updateFirmware,"address");
		if (cJSON_IsString(address)) {
			cfg->updateFirmware.address = address->valuestring;
		}
	}

	const cJSON* wifi = cJSON_GetObjectItemCaseSensitive(jData,"wifi");
	if (cJSON_IsObject(wifi)) {
		const cJSON* ssid = cJSON_GetObjectItemCaseSensitive(wifi,"ssid");
		if (cJSON_IsString(ssid)) {
			cfg->wifi.ssid = ssid->valuestring;
		}
		const cJSON* passwd = cJSON_GetObjectItemCaseSensitive(wifi,"password");
		if (cJSON_IsString(passwd)) {
			cfg->wifi.passwd = passwd->valuestring;
		}
	}

	const cJSON* prod = cJSON_GetObjectItemCaseSensitive(jData,"prod");
	if (cJSON_IsObject(prod)) {
		const cJSON* serialNumber = cJSON_GetObjectItemCaseSensitive(prod,"serialNumber");
		if (cJSON_IsString(serialNumber)) {
			cfg->prod.serialNumber = serialNumber->valuestring;
		}
	}

	const cJSON* simcard = cJSON_GetObjectItemCaseSensitive(jData,"simcard");
	if (cJSON_IsArray(simcard)) {
		for (int i=0;i<cJSON_GetArraySize(simcard);i++) {
			const cJSON* card = cJSON_GetArrayItem(simcard,i);
			if (cJSON_IsObject(card)) {
    			SimCardInfo item;
				const cJSON* apn = cJSON_GetObjectItemCaseSensitive(card,"apn");
				if (cJSON_IsString(apn)) {
					item.apn = apn->valuestring;
				}
				const cJSON* user = cJSON_GetObjectItemCaseSensitive(card,"user");
				if (cJSON_IsString(user)) {
					item.user = user->valuestring;
				}
				const cJSON* pwd = cJSON_GetObjectItemCaseSensitive(card,"pwd");
				if (cJSON_IsString(pwd)) {
					item.pwd = pwd->valuestring;
				}
				const cJSON* connId = cJSON_GetObjectItemCaseSensitive(card,"connId");
				if (cJSON_IsNumber(connId)) {
					item.connId = connId->valueint;
				}
				const cJSON* direct_mode = cJSON_GetObjectItemCaseSensitive(card,"direct_mode");
				if (cJSON_IsNumber(direct_mode)) {
					item.direct_mode = direct_mode->valueint;
				}
				cfg->simcard.push_back(item);
			}
		}
	}

	/*
	 * Freeing memory
	 */
	cJSON_Delete(jData);

	return 0;
}
