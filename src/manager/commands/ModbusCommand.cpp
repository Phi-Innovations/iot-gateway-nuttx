#include "ModbusCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* ModbusCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonInt("slaveAddr",input,data->cfg->modbus.slaveAddr);
    Utils::extractJsonInt("baudrate",input,data->cfg->modbus.baudrate);
    Utils::extractJsonChar("parity",input,data->cfg->modbus.parity);
    Utils::extractJsonInt("databits",input,data->cfg->modbus.dataBit);
    Utils::extractJsonInt("stopbits",input,data->cfg->modbus.stopBits);
    Utils::extractJsonInt("tcpPort",input,data->cfg->modbus.tcpPort);

    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("modbus",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("modbus",data->cfg->deviceId);
    }

    return output;
}