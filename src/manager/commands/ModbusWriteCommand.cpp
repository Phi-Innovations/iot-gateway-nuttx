#include "ModbusWriteCommand.h"
#include "Utils.h"
#include "data/ModbusInfo.h"

#include <syslog.h>

cJSON* ModbusWriteCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * Retrieve the slave address to get the information
     */
    const cJSON* jSlave = cJSON_GetObjectItemCaseSensitive(input,"address");
    if (jSlave == NULL) {
        return Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Could not find field 'address'");
    }
    if (!cJSON_IsNumber(jSlave)) {
        return Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Invalid field 'address' value");
    }
    int slaveAddress = jSlave->valueint;
    /*
     * Search for the requested slave address
     */
    ModbusInfo *modbus = NULL;
    for (const auto& slave : data->slaveMap->slaves) {
        ModbusInfo *mb = (ModbusInfo*)slave.capture;
        if (mb->address == slaveAddress) {
            modbus = mb;
        }
    }
    if (modbus == NULL) {
        return Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Slave address not found");
    }
    /*
     * Sanity check: verify the presence of the correct field registers
     */
    cJSON* errOutput = NULL;
    const cJSON* reglist = cJSON_GetObjectItemCaseSensitive(input,"registers");
    if (reglist == NULL) {
        return Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Could not find field 'registers'");
    }
    /*
     * Scan input address list
     */
    const cJSON* regItem;
    cJSON_ArrayForEach(regItem, reglist) {
        /*
         * Extract the register number
         */
        int regAddress = -1;
        const cJSON* jRegister = cJSON_GetObjectItemCaseSensitive(regItem,"register");
        if (jRegister != NULL) {
            if (cJSON_IsNumber(jRegister)) {
                regAddress = jRegister->valueint;
            }
        }
        else {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Invalid field 'register'");
            break;
        }
        /*
         * Retrieve the associated command
         */
        int regCommand = -1;
        const cJSON* jCommand = cJSON_GetObjectItemCaseSensitive(regItem,"command");
        if (jCommand != NULL) {
            if (cJSON_IsNumber(jCommand)) {
                regCommand = jCommand->valueint;
            }
        }
        else {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Invalid field 'command'");
            break;
        }
        /*
         * Retrieve the associated type
         */
        int regType = -1;
        const cJSON* jType = cJSON_GetObjectItemCaseSensitive(regItem,"type");
        if (jType != NULL) {
            if (cJSON_IsNumber(jType)) {
                regType = jType->valueint;
            }
        }
        else {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Invalid field 'type'");
            break;
        }
        /*
         * Perform sanity checks
         */
        if ((regAddress == -1) || (regCommand == -1) || (regType == -1)) {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Wrong register info from JSON");
            break;
        }
        /*
         * Check if the register exists
         */
        if (modbus->map.find(regAddress) == modbus->map.end()) {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Register address not found");
            break;
        }
        /*
         * Check if the provided type matches the internal type
         */
        if (modbus->map[regAddress].type != regType) {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Invalid register type");
            break;
        }
        /*
         * Check if the provided type matches the internal type
         */
        if (modbus->map[regAddress].command != regCommand) {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Invalid register command");
            break;
        }
        /*
         * Retrieve the associated type
         */
        double regVal = -1;
        const cJSON* jVal = cJSON_GetObjectItemCaseSensitive(regItem,"value");
        if (jVal != NULL) {
            if (cJSON_IsNumber(jVal)) {
                regVal = jType->valuedouble;
            }
        }
        else {
            errOutput = Utils::buildJsonERROR("modbus_write",data->cfg->deviceId,"Invalid field 'type'");
            break;
        }
        /*
         * Store the new value
         */
        modbus->map[regAddress].assignValue(regVal);
    }

    /*
     * In case of error, clean the already filled output buffer
     * and returns the error message. Otherwise, returns the response
     */
    if (errOutput != NULL) {
        return errOutput;
    }

    return Utils::buildJsonOK("modbus_write",data->cfg->deviceId);
}