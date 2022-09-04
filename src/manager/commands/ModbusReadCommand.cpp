#include "ModbusReadCommand.h"
#include "Utils.h"
#include "data/ModbusInfo.h"

#include <syslog.h>

cJSON* ModbusReadCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * Retrieve the slave address to get the information
     */
    const cJSON* jSlave = cJSON_GetObjectItemCaseSensitive(input,"address");
    if (jSlave == NULL) {
        return Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Could not find field 'address'");
    }
    if (!cJSON_IsNumber(jSlave)) {
        return Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Invalid field 'address' value");
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
        return Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Slave address not found");
    }
    /*
     * Sanity check for register list
     */
    const cJSON* reglist = cJSON_GetObjectItemCaseSensitive(input,"registers");
    if (reglist == NULL) {
        return Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Could not find field 'registers'");
    }
    /*
     * Scan the request information and build the response output
     */
    cJSON* errOutput = NULL;
    cJSON *outValue = cJSON_CreateObject();
    cJSON* jRegisters = cJSON_AddArrayToObject(outValue,"registers");
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
            errOutput = Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Invalid field 'register'");
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
            errOutput = Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Invalid field 'command'");
            break;
        }
        /*
         * Sanity checks
         */
        if ((regAddress == -1) || (regCommand == -1)) {
            errOutput = Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Invalid field values in JSON");
            break;
        }
        if (modbus->map.find(regAddress) == modbus->map.end()) {
            errOutput = Utils::buildJsonERROR("modbus_read",data->cfg->deviceId,"Register address not found");
            break;
        }
        /*
         * In case of error during type read, exit the loop
         */
        if (errOutput) {
            break;
        }
        /*
         * Create the JSON output
         */
        cJSON* jNewRegister = cJSON_CreateObject();
        cJSON_AddNumberToObject(jNewRegister,"register",regAddress);
        cJSON_AddNumberToObject(jNewRegister,"value",modbus->map[regAddress].exportValue());
        
        /*
         * Add the item to the output array
         */
        cJSON_AddItemToArray(jRegisters, jNewRegister);
    }

    /*
     * In case of error, clean the already filled output buffer
     * and returns the error message. Otherwise, returns the response
     */
    if (errOutput != NULL) {
        if (outValue != NULL) {
            cJSON_Delete(outValue);
        }
        return errOutput;
    }

    /*
     * Initialize and return the output response
     */
    cJSON* output = cJSON_CreateObject();
    cJSON_AddStringToObject(output,"command","modbus_read");
    cJSON_AddNumberToObject(output,"deviceId",data->cfg->deviceId);
    cJSON_AddStringToObject(output,"result","OK");
    cJSON_AddItemToObject(output,"value",outValue);

    return output;
}