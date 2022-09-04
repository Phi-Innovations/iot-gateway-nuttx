#pragma once
#include "CommandIF.h"

class ConfigCommand : public CommandIF {
private:
    static cJSON* buildMqttConfigResponse(Configuration *cfg);
    static cJSON* buildEthernetConfigResponse(Configuration *cfg);
    static cJSON* buildWifiConfigResponse(Configuration *cfg);
    static cJSON* buildGsmConfigResponse(Configuration *cfg);
    static cJSON* buildModbusConfigResponse(Configuration *cfg);
    static cJSON* buildDeviceIdConfigResponse(Configuration *cfg);
    static cJSON* buildOperationConfigResponse(Configuration *cfg);
    static cJSON* buildDatetimeConfigResponse(Configuration *cfg);
    static cJSON* buildScanGeneralConfigResponse(Configuration *cfg);
    static cJSON* buildMapConfigResponse(SystemData *data);
    static cJSON* buildCertResponse(SystemData *data);
public:
    cJSON* execute(const std::string& input, SystemData *data);
};
