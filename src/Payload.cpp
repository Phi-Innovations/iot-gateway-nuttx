#include "Payload.h"
#include "defs.h"
#include "data/ModbusInfo.h"

#include <syslog.h>

/*
 * Input: file buffer containing json structure
 * Output: Json structure to be published
 */
cJSON* Payload::buildStandard(int deviceId, int slaveNumber, char *data, SlaveMap* map) {
    /*
     * Read input file
     */
    cJSON *input = cJSON_Parse(data);
    if (input == NULL) {
        syslog(LOG_ERR, "Problem parsing register file\n");
        return NULL;
    }
    /*
     * Create output structure
     */
    cJSON *output = cJSON_CreateObject();
    /*
     * Add slave number information
     */
    cJSON_AddNumberToObject(output,"slaveNumber",slaveNumber);
    cJSON_AddNumberToObject(output,"deviceId",deviceId);
    /*
     * Get timestamp and add into the output structure
     */
    const cJSON* jTimestamp = cJSON_GetObjectItemCaseSensitive(input,INT_JSON_TIMESTAMP);
    if (jTimestamp != NULL) {
        if (cJSON_IsString(jTimestamp)) {
            /*
             * Add to the output
             */
            cJSON_AddStringToObject(output,"timestamp",jTimestamp->valuestring);
        }
        else {
            syslog(LOG_ERR, "Field 'timestamp' is not a string\n");
            cJSON_Delete(input);
            cJSON_Delete(output);
            return NULL;
        }
    }
    else {
        syslog(LOG_ERR, "Field 'timestamp' not found\n");
        cJSON_Delete(input);
        cJSON_Delete(output);
        return NULL;
    }
    /*
     * Add the registers
     */
    const cJSON* addresses = cJSON_GetObjectItemCaseSensitive(input,INT_JSON_REGISTERS);
    if (addresses != NULL) {
        if (cJSON_IsArray(addresses)) {
            cJSON *outputRegs = cJSON_AddArrayToObject(output,"registers");
            /*
             * Scan the array
             */
            const cJSON* address;
            cJSON_ArrayForEach(address, addresses) {
                std::string registerName;                
                /*
                 * Extract the register and get its name
                 */
                cJSON* jAddress = cJSON_GetObjectItemCaseSensitive(address,INT_JSON_REGISTER);
                if (jAddress != NULL) {
                    if (cJSON_IsNumber(jAddress)) {
                        /*
                         * Setup the register name from the register number
                         * Search for the name inside the structure
                         */
                        bool found = false;
                        for(const auto& slave : map->slaves) {
                            ModbusInfo *modbus = (ModbusInfo*)slave.capture;
                            if (modbus->address == slaveNumber) {
                                if (modbus->map.find(jAddress->valueint) != modbus->map.end()) {
                                    found = true;
                                    registerName = modbus->map[jAddress->valueint].name;
                                }
                            }
                        }
                        if (found == false) {
                            syslog(LOG_ERR,"Payload: Slave number %d or register %d not found\n",
                                        slaveNumber, jAddress->valueint);
                            cJSON_Delete(input);
                            cJSON_Delete(output);
                            return NULL;
                        }
                    }
                    else {
                        syslog(LOG_ERR,"Payload: Field 'register' is not a number\n");
                        cJSON_Delete(input);
                        cJSON_Delete(output);
                        return NULL;
                    }
                }
                else {
                    syslog(LOG_ERR,"Could not find the field 'register'\n");
                    cJSON_Delete(input);
                    cJSON_Delete(output);
                    return NULL;
                }
                /*
                 * Get the saved value
                 */
                cJSON* jValue = cJSON_GetObjectItemCaseSensitive(address,INT_JSON_VALUE);
                if (jValue != NULL) {
                    if (cJSON_IsNumber(jValue)) {
                        /*
                         * Setup the register name from the register number
                         */
                        cJSON* outputReg = cJSON_CreateObject();
                        cJSON_AddNumberToObject(outputReg,registerName.c_str(),jValue->valuedouble);
                        cJSON_AddItemToArray(outputRegs, outputReg);
                    }
                    else {
                        syslog(LOG_ERR,"Field 'value' is not a number\n");
                        cJSON_Delete(input);
                        cJSON_Delete(output);
                        return NULL;
                    }
                }
                else {
                    syslog(LOG_ERR,"Could not find the field 'value'\n");
                    cJSON_Delete(input);
                    cJSON_Delete(output);
                    return NULL;
                }
            }
        }
        else {
            syslog(LOG_ERR, "Field 'registers' is not an array\n");
            cJSON_Delete(input);
            cJSON_Delete(output);
            return NULL;
        }
    }
    else {
        syslog(LOG_ERR, "Field 'registers' not found\n");
        cJSON_Delete(input);
        cJSON_Delete(output);
        return NULL;
    }

    /*
     * Free internal structure used to read input file
     */
    cJSON_Delete(input);

    return output;
}

/*
 * Input: file buffer containing json structure
 * Output: Json structure to be published
 */
cJSON* Payload::buildKron(int slaveNumber, char *data, SlaveMap* map) {
    /*
     * Read input file
     */
    cJSON *input = cJSON_Parse(data);
    if (input == NULL) {
        syslog(LOG_ERR, "Payload: Kron: Problem parsing register file\n");
        return NULL;
    }
    /*
     * Create output structure
     */
    cJSON *output = cJSON_CreateArray();
    cJSON *outItem = cJSON_CreateObject();
    /* Header */
    cJSON_AddStringToObject(outItem,"variable","data");
    /* Timestamp */
    const cJSON* jTimestamp = cJSON_GetObjectItemCaseSensitive(input,INT_JSON_TIMESTAMP);
    if (jTimestamp != NULL) {
        if (cJSON_IsString(jTimestamp)) {
            /*
             * Add to the output
             */
            cJSON_AddStringToObject(outItem,"time",jTimestamp->valuestring);
        }
        else {
            syslog(LOG_ERR, "Payload: Kron: Field 'timestamp' is not a string\n");
            cJSON_Delete(input);
            cJSON_Delete(output);
            return NULL;
        }
    }
    else {
        syslog(LOG_ERR, "Payload: Kron: Field 'timestamp' not found\n");
        cJSON_Delete(input);
        cJSON_Delete(output);
        return NULL;
    }
    /*
     * Add the registers
     */
    cJSON *jMetadata = cJSON_CreateObject();
    const cJSON* addresses = cJSON_GetObjectItemCaseSensitive(input,INT_JSON_REGISTERS);
    if (addresses != NULL) {
        if (cJSON_IsArray(addresses)) {
            /*
             * Scan the array
             */
            const cJSON* address;
            cJSON_ArrayForEach(address, addresses) {
                std::string registerName;                
                /*
                 * Extract the register and get its name
                 */
                cJSON* jAddress = cJSON_GetObjectItemCaseSensitive(address,INT_JSON_REGISTER);
                if (jAddress != NULL) {
                    if (cJSON_IsNumber(jAddress)) {
                        /*
                         * Setup the register name from the register number
                         * Search for the name inside the structure
                         */
                        bool found = false;
                        for(const auto& slave : map->slaves) {
                            ModbusInfo *modbus = (ModbusInfo*)slave.capture;
                            if (modbus->address == slaveNumber) {
                                if (modbus->map.find(jAddress->valueint) != modbus->map.end()) {
                                    found = true;
                                    registerName = modbus->map[jAddress->valueint].name;
                                }
                            }
                        }
                        if (found == false) {
                            syslog(LOG_ERR,"Payload: Slave number %d or register %d not found\n",
                                        slaveNumber, jAddress->valueint);
                            cJSON_Delete(input);
                            cJSON_Delete(output);
                            return NULL;
                        }
                    }
                    else {
                        syslog(LOG_ERR,"Payload: Field 'register' is not a number\n");
                        cJSON_Delete(input);
                        cJSON_Delete(output);
                        return NULL;
                    }
                }
                else {
                    syslog(LOG_ERR,"Could not find the field 'register'\n");
                    cJSON_Delete(input);
                    cJSON_Delete(output);
                    return NULL;
                }
                /*
                 * Get the saved value
                 */
                cJSON* jValue = cJSON_GetObjectItemCaseSensitive(address,INT_JSON_VALUE);
                if (jValue != NULL) {
                    if (cJSON_IsNumber(jValue)) {
                        /*
                         * Setup the register name from the register number
                         */
                        cJSON_AddNumberToObject(jMetadata,registerName.c_str(),jValue->valuedouble);
                    }
                    else {
                        syslog(LOG_ERR,"Field 'value' is not a number\n");
                        cJSON_Delete(input);
                        cJSON_Delete(output);
                        return NULL;
                    }
                }
                else {
                    syslog(LOG_ERR,"Could not find the field 'value'\n");
                    cJSON_Delete(input);
                    cJSON_Delete(output);
                    return NULL;
                }
            }
        }
        else {
            syslog(LOG_ERR, "Field 'registers' is not an array\n");
            cJSON_Delete(input);
            cJSON_Delete(output);
            return NULL;
        }
    }
    else {
        syslog(LOG_ERR, "Field 'registers' not found\n");
        cJSON_Delete(input);
        cJSON_Delete(output);
        return NULL;
    }
    cJSON_AddItemToObject(outItem,"metadata",jMetadata);
    /* Insert the item to the output array */
    cJSON_AddItemToArray(output,outItem);

    /*
     * Free internal structure used to read input file
     */
    cJSON_Delete(input);

    return output;
}
