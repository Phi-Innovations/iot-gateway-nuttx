#include "ConfigCommand.h"
#include "Utils.h"
#include "defs.h"
#include <syslog.h>
#include <netutils/base64.h>

cJSON* ConfigCommand::execute(const std::string& input, SystemData *data) {
    syslog(LOG_DEBUG, "Starting Config command: %s\n", input.c_str());

    cJSON* output = NULL;
    if (input == "mqtt") {
        output = buildMqttConfigResponse(data->cfg);
    } else if (input == "ethernet") {
        output = buildEthernetConfigResponse(data->cfg);
    } else if (input == "wifi") {
        output = buildWifiConfigResponse(data->cfg);
    } else if (input == "gsm") {
        output = buildGsmConfigResponse(data->cfg);
    } else if (input == "modbus") {
        output = buildModbusConfigResponse(data->cfg);
    } else if (input == "datetime") {
        output = buildDatetimeConfigResponse(data->cfg);
    } else if (input == "deviceid") {
        output = buildDeviceIdConfigResponse(data->cfg);
    } else if (input == "operation") {
        output = buildOperationConfigResponse(data->cfg);
    } else if (input == "scanGeneral") {
        output = buildScanGeneralConfigResponse(data->cfg);
    } else if (input == "scanMap") {
        output = buildMapConfigResponse(data);
    } else if (input == "cert") {
        output = buildCertResponse(data);
    } else {
        syslog(LOG_DEBUG, "Config command not found: %s\n", input.c_str());
        output = Utils::buildJsonERROR(input,data->cfg->deviceId,"Config command not found");
    }

    return output;
}

cJSON* ConfigCommand::buildMqttConfigResponse(Configuration *cfg) {

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","mqtt");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value,"serverAddress",cfg->mqtt.server.address.c_str());
    cJSON_AddNumberToObject(value,"serverPort",cfg->mqtt.server.port);
    cJSON_AddStringToObject(value,"clientId",cfg->mqtt.cliendId.c_str());
    cJSON_AddStringToObject(value,"username",cfg->mqtt.username.c_str());
    cJSON_AddStringToObject(value,"password",cfg->mqtt.password.c_str());
    cJSON_AddStringToObject(value,"pubTopic",cfg->mqtt.pubTopic.c_str());
    cJSON_AddStringToObject(value,"rspTopic",cfg->mqtt.rspTopic.c_str());
    cJSON_AddStringToObject(value,"cmdTopic",cfg->mqtt.cmdTopic.c_str());
    cJSON_AddNumberToObject(value,"connectionMode",cfg->connectionMode);
    cJSON_AddNumberToObject(value,"useTls",cfg->mqtt.useTls);
    cJSON_AddNumberToObject(value,"tlsAuthMode",cfg->mqtt.tlsAuthMode);
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildEthernetConfigResponse(Configuration *cfg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","ethernet");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value,"ip",cfg->net.ipAddr.c_str());
    cJSON_AddStringToObject(value,"netmask",cfg->net.netmask.c_str());
    cJSON_AddStringToObject(value,"gateway",cfg->net.gateway.c_str());
    cJSON_AddStringToObject(value,"dns",cfg->net.dns.c_str());
    cJSON_AddStringToObject(value,"mac",cfg->net.macAddress.c_str());
    cJSON_AddStringToObject(value,"dhcp",std::to_string(cfg->net.isDHCP).c_str());
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildWifiConfigResponse(Configuration *cfg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","wifi");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();

    cJSON_AddStringToObject(value,"ip",cfg->net_wifi.ipAddr.c_str());
    cJSON_AddStringToObject(value,"netmask",cfg->net_wifi.netmask.c_str());
    cJSON_AddStringToObject(value,"gateway",cfg->net_wifi.gateway.c_str());
    cJSON_AddStringToObject(value,"dns",cfg->net_wifi.dns.c_str());
    cJSON_AddStringToObject(value,"dhcp",std::to_string(cfg->net_wifi.isDHCP).c_str());
    cJSON_AddStringToObject(value,"ssid",cfg->wifi.ssid.c_str());
    cJSON_AddStringToObject(value,"password",cfg->wifi.passwd.c_str());
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildGsmConfigResponse(Configuration *cfg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","gsm");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();

    cJSON_AddStringToObject(value,"gsm1apn",cfg->simcard[0].apn.c_str());
    cJSON_AddStringToObject(value,"gsm1user",cfg->simcard[0].user.c_str());
    cJSON_AddStringToObject(value,"gsm1pwd",cfg->simcard[0].pwd.c_str());
    cJSON_AddStringToObject(value,"gsm2apn",cfg->simcard[1].apn.c_str());
    cJSON_AddStringToObject(value,"gsm2user",cfg->simcard[1].user.c_str());
    cJSON_AddStringToObject(value,"gsm2pwd",cfg->simcard[1].pwd.c_str());
    cJSON_AddNumberToObject(value,"gsmDefault",cfg->usedSimNb);
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildModbusConfigResponse(Configuration *cfg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","modbus");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();

    /* Convert slave address to hex value */
    char slaveHex[8];
    sprintf(slaveHex, "%02X", cfg->modbus.slaveAddr);

    cJSON_AddStringToObject(value,"slaveAddr", slaveHex);
    cJSON_AddNumberToObject(value,"baudrate",cfg->modbus.baudrate);
    cJSON_AddStringToObject(value,"parity", std::string(1, cfg->modbus.parity).c_str());
    cJSON_AddNumberToObject(value,"databits",cfg->modbus.dataBit);
    cJSON_AddNumberToObject(value,"stopbits",cfg->modbus.stopBits);
    cJSON_AddNumberToObject(value,"tcpPort",cfg->modbus.tcpPort);
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildDatetimeConfigResponse(Configuration *cfg) {
    struct timespec ts;
    struct tm tm;
    int ret;
    bool correct = true;
    char datetime[24] = { 0 };

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","datetime");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);

    ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (ret < 0) {
        syslog(LOG_ERR, "Problem reading current date time\n");
        cJSON_AddStringToObject(root,"result","ERROR");
        cJSON_AddStringToObject(root,"description","Problem reading clock");
        correct = false;
    }

    if (correct == true) {
        if (gmtime_r((FAR const time_t *)&ts.tv_sec, &tm) == NULL) {
            syslog(LOG_ERR, "Problem formatting date time read\n");
            cJSON_AddStringToObject(root,"result","ERROR");
            cJSON_AddStringToObject(root,"description","Problem formatting reading clock");
            correct = false;  
        }
        else {
            tm.tm_year += 1900;
        }
    }

    if (correct == true) {
        memset(datetime,0,sizeof(datetime));
        sprintf(datetime,"%04d-%02d-%02dT%02d:%02d:%02d",tm.tm_year, tm.tm_mon, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec);
        syslog(LOG_DEBUG, "Datetime captured: %s\n",datetime);
        cJSON_AddStringToObject(root,"result","OK");
        cJSON_AddStringToObject(root,"value",datetime);
    }

    return root;
}

cJSON* ConfigCommand::buildDeviceIdConfigResponse(Configuration *cfg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","deviceId");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();
    cJSON_AddNumberToObject(value,"deviceId",cfg->deviceId);
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildOperationConfigResponse(Configuration *cfg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","operation");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();

    cJSON_AddNumberToObject(value,"mode",cfg->operationMode);
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildScanGeneralConfigResponse(Configuration *cfg) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","scanGeneral");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();

    cJSON_AddNumberToObject(value,"payloadType",cfg->payloadType);
    cJSON_AddNumberToObject(value,"transmissionMode",cfg->transmissionMode);
    /* Data used internally is in seconds. Must output to minutes */
    cJSON_AddNumberToObject(value,"scanInterval",(cfg->scanInterval / 60));
    /* Data used internally is in seconds. Must output to minutes */
    cJSON_AddNumberToObject(value,"sendInterval",(cfg->sendInterval / 60));
    cJSON_AddNumberToObject(value,"cmdInterval",cfg->cmdInterval);
    cJSON_AddNumberToObject(value,"operationMode",cfg->operationMode);
    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildMapConfigResponse(SystemData *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","scanMap");
    cJSON_AddNumberToObject(root,"deviceId",data->cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = data->slaveMap->build();

    cJSON_AddItemToObject(root,"value",value);

    return root;
}

cJSON* ConfigCommand::buildCertResponse(SystemData *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","cert");
    cJSON_AddNumberToObject(root,"deviceId",data->cfg->deviceId);

    size_t len = 0;
    char *certFile = Utils::loadBufferFromFile(CERTIFICATE_FILE,&len);
    if (certFile == NULL) {
        cJSON_AddStringToObject(root,"result","ERROR");
        cJSON_AddStringToObject(root,"description","Problem opening certificate file");
    }
    else {
        size_t certLen = 0;
        char *cert = (char*)base64_encode(certFile,strlen(certFile),NULL,&certLen);
        if (cert == NULL) {
            cJSON_AddStringToObject(root,"result","ERROR");
            cJSON_AddStringToObject(root,"description","Problem encoding certificate file");
        }
        else {
            cJSON_AddStringToObject(root,"result","OK");
            cJSON_AddStringToObject(root,"value",cert);
            /*
             * Free internal buffer
             */
            free(cert);
        }
        /*
         * Free internal buffer
         */
        free(certFile);
    }

    return root;
}
