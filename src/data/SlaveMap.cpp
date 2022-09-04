#include "SlaveMap.h"
#include "Utils.h"
#include "ModbusInfo.h"
#include "ProtocolMqttInfo.h"

#include <string>
#include <string.h>
#include <syslog.h>

#include "defs.h"

SlaveMap::SlaveMap() {
    /*
     * Check if file exists
     */
    if (!Utils::fileExists(MODBUS_MAP)) {
        syslog(LOG_ERR, "SlaveMap: Modbus map file not found. Creating one\n");
        create();
    }
    /*
     * Load the file
     */
    if (load() < 0) {
        syslog(LOG_ERR, "SlaveMap: Problem loading modbus map file\n");
    }
    syslog(LOG_INFO,"SlaveMap: Modbus map file loaded\n");
}

SlaveMap::~SlaveMap() {
    /* Clear the slaves */
    for (auto slave : slaves) {
        /*
         * Check capture structure
         */
        if (slave.capture != NULL) {
            if ((slave.capture->protocol == CAPTURE_PROTOCOL_MODBUS_RTU) || 
                    (slave.capture->protocol == CAPTURE_PROTOCOL_MODBUS_TCP)) {
                ((ModbusInfo*)slave.capture)->map.clear();
            }
            else {
                syslog(LOG_WARNING,"SlaveMap: Unknown prototocol type: %d\n",slave.capture->protocol);
            }
            /*
             * Remove the object
             */
            delete slave.capture;
            slave.capture = NULL;
        }
        /*
         * Check transmission structure
         */
        if (slave.transmission != NULL) {
            /*
             * Remove the object
             */
            delete slave.transmission;
            slave.transmission = NULL;
        }
    }
    slaves.clear();
}

int SlaveMap::create(void) {
    const char *jOutput = "{ \
        \"addresses\": [{ \
            \"transmission\": { \
                \"protocol\": 1, \
                \"hostAddress\": \"54.191.223.33\", \
                \"port\": \"8883\", \
                \"username\": \"phi\", \
                \"password\": \"phi\", \
                \"payloadType\": 0 \
            }, \
            \"capture\": { \
                \"protocol\": 1, \
                \"modbus\": { \
                    \"cmd4Offset\": 30001, \
                    \"cmd3Offset\": 0, \
                    \"address\": 1, \
                    \"serverAddress\": \"192.168.0.1\", \
                    \"serverPort\": 1502, \
                    \"registers\": [{ \
                            \"register\": 30053, \
                            \"type\": 2, \
                            \"name\": \"eap\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30003, \
                            \"type\": 2, \
                            \"name\": \"u0\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30005, \
                            \"type\": 2, \
                            \"name\": \"i0\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30013, \
                            \"type\": 2, \
                            \"name\": \"p0\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30007, \
                            \"type\": 2, \
                            \"name\": \"fp\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30015, \
                            \"type\": 2, \
                            \"name\": \"f\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30055, \
                            \"type\": 2, \
                            \"name\": \"erp\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30063, \
                            \"type\": 2, \
                            \"name\": \"da\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30009, \
                            \"type\": 2, \
                            \"name\": \"s0\", \
                            \"command\": 1 \
                        }, \
                        { \
                            \"register\": 30011, \
                            \"type\": 2, \
                            \"name\": \"q0\", \
                            \"command\": 1 \
                        } \
                    ] \
                } \
            } \
        }] \
    }";

    size_t fileLen = strlen(jOutput);

    /*
     * Save output to file
     */
    FILE *fp = NULL;
    fp = fopen(MODBUS_MAP,"w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Problem opening modbus map file for writing: %s\n", MODBUS_MAP);
        return -1;
    }
    
    size_t nwrite = fwrite(jOutput,1,fileLen,fp);
    if (nwrite < 0) {
        syslog(LOG_ERR, "Problem writing modbus map file\n");
    }
    else if (nwrite != fileLen) {
        syslog(LOG_WARNING, "Modbus map file not written completely");
    }

    fclose(fp);
    return 0;
}

int SlaveMap::load(void) {
    /*
     * Open the configuration file
     */
    FILE *fp;
    fp = fopen(MODBUS_MAP,"r");
    if (fp == NULL) {
        syslog(LOG_ERR, "Unable to open modbus map file: %s\n", MODBUS_MAP);
        return -1;
    }

    /*
     * Get the file size
     */
    fseek(fp, 0, SEEK_END);
    int len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /*
     * Allocate memory for reading data
     */
    char *data = (char*)malloc(len + 1);
    if (data == NULL) {
        syslog(LOG_ERR, "Problem initializing memory for reading modbus map file: %s\n", MODBUS_MAP);
        fclose(fp);
        return -1;
    }
    memset(data,0,len+1);

    /*
     * Read file content
     */
    int nread = fread(data,1,len,fp);
    if (nread != len) {
        syslog(LOG_ERR, "Problem reading modbus map file: %s\n", MODBUS_MAP);
        free(data);
        fclose(fp);
        return -1;
    }

    cJSON *config = cJSON_Parse(data);
    if (config == NULL) {
        syslog(LOG_ERR, "Problem parsing modbus map file: %s\n", MODBUS_MAP);
        return -1;
    }

    int ret = process(config);

    cJSON_Delete(config);

    /*
     * Ending
     */
    free(data);
    fclose(fp);

    return ret;
}

void SlaveMap::extractTransmissionMqtt(const cJSON* jsonTransmission, SlaveInfo& slave) {
    /*
     *  Retrives the hostAddress
     */
    std::string hostAddress;
    const cJSON* jHostAddress = cJSON_GetObjectItemCaseSensitive(jsonTransmission,"hostAddress");
    if (jHostAddress != NULL) {
        if (cJSON_IsString(jHostAddress)) {
            hostAddress = jHostAddress->valuestring;
            // syslog(LOG_DEBUG, "Initializing transmisson.hostAddress to %s\n", slave.transmission.hostAddress.c_str());
        }
        else {
            syslog(LOG_WARNING, "Field 'hostAddress' is not a string\n");
        }
    }
    else {
        syslog(LOG_WARNING, "Field 'hostAddress' not found\n");
    }

    /*
     *  Retrives the port
     */
    std::string port;
    const cJSON* jPort = cJSON_GetObjectItemCaseSensitive(jsonTransmission,"port");
    if (jPort != NULL) {
        if (cJSON_IsString(jPort)) {
            port = jPort->valuestring;
        }
        else {
            syslog(LOG_WARNING, "Field 'port' is not a string\n");
        }
    }
    else {
        syslog(LOG_WARNING, "Field 'port' not found\n");
    }

    /*
     *  Retrives the username
     */
    std::string username;
    const cJSON* jUsername = cJSON_GetObjectItemCaseSensitive(jsonTransmission,"username");
    if (jUsername != NULL) {
        if (cJSON_IsString(jUsername)) {
            username = jUsername->valuestring;
        }
        else {
            syslog(LOG_WARNING, "Field 'username' is not a string\n");
        }
    }
    else {
        syslog(LOG_WARNING, "Field 'username' not found\n");
    }

    /*
     *  Retrives the password
     */
    std::string password;
    const cJSON* jPassword = cJSON_GetObjectItemCaseSensitive(jsonTransmission,"password");
    if (jPassword != NULL) {
        if (cJSON_IsString(jPassword)) {
            password = jPassword->valuestring;
        }
        else {
            syslog(LOG_WARNING, "Field 'password' is not a string\n");
        }
    }
    else {
        syslog(LOG_WARNING, "Field 'password' not found\n");
    }

    /*
     *  Retrives the payloadType
     */
    int payloadType = PAYLOAD_TYPE_STD;
    const cJSON* jPayloadType = cJSON_GetObjectItemCaseSensitive(jsonTransmission,"payloadType");
    if (jPayloadType != NULL) {
        if (cJSON_IsNumber(jPayloadType)) {
            payloadType = jPayloadType->valueint;
        }
        else {
            syslog(LOG_WARNING, "Field 'payloadType' is not a number\n");
        }
    }
    else {
        syslog(LOG_WARNING, "Field 'payloadType' not found\n");
    }

    /*
     * Initialize the output structure to be set at the list
     */
    ProtocolMqttInfo *mqtt = new ProtocolMqttInfo();
    mqtt->hostAddress = hostAddress;
    mqtt->port = port;
    mqtt->username = username;
    mqtt->password = password;
    mqtt->payloadType = payloadType;
    /*
     * Add the new structure into the list
     */
    if (slave.transmission != NULL) {
        delete slave.transmission;
        slave.transmission = NULL;
    }
    slave.transmission = (TransmissionInfo*)mqtt;

    syslog(LOG_INFO,"SlaveMap: Added MQTT protocol config: %s %s %s %s %d\n",
            ((ProtocolMqttInfo*)slave.transmission)->hostAddress.c_str(),
            ((ProtocolMqttInfo*)slave.transmission)->port.c_str(),
            ((ProtocolMqttInfo*)slave.transmission)->username.c_str(),
            ((ProtocolMqttInfo*)slave.transmission)->password.c_str(),
            ((ProtocolMqttInfo*)slave.transmission)->payloadType);
}

void SlaveMap::extractTransmission(int protocol, const cJSON* jsonTransmission, SlaveInfo& slave) {
    
    /*
     * Continue the evaluation based on the protocol type
     */
    switch (protocol) {
    case TRANSMISSION_PROTOCOL_MQTT:
        extractTransmissionMqtt(jsonTransmission,slave);
        break;
    default:
        syslog(LOG_ERR, "Unknown protocol type: %d\n",protocol);
        break;
    }

    /*
     * If everything is fine, update the protocol configuration
     */
    if (slave.transmission != NULL) {
        slave.transmission->protocol = protocol;
    }
}

void SlaveMap::extractCaptureModbus(const cJSON* jsonCapture, SlaveInfo& slave) {
    /*
     *  Retrives the modbus object
     */
    const cJSON* jsonModbus = cJSON_GetObjectItemCaseSensitive(jsonCapture,"modbus");
    if (jsonModbus != NULL) {
        if (cJSON_IsObject(jsonModbus)) {
            /*
             *  Retrives the cmd4Offset
             */
            int cmd4Offset = 0;
            const cJSON* jCmd4Offset = cJSON_GetObjectItemCaseSensitive(jsonModbus,"cmd4Offset");
            if (jCmd4Offset != NULL) {
                if (cJSON_IsNumber(jCmd4Offset)) {
                    cmd4Offset = jCmd4Offset->valueint;
                }
                else {
                    syslog(LOG_WARNING, "Field 'cmd4Offset' is not a number\n");
                }
            }
            else {
                syslog(LOG_WARNING, "Field 'cmd4Offset' not found\n");
            }

            /*
             *  Retrives the cmd3Offset
             */
            int cmd3Offset = 0;
            const cJSON* jCmd3Offset = cJSON_GetObjectItemCaseSensitive(jsonModbus,"cmd3Offset");
            if (jCmd3Offset != NULL) {
                if (cJSON_IsNumber(jCmd3Offset)) {
                    cmd3Offset = jCmd3Offset->valueint;
                }
                else {
                    syslog(LOG_WARNING, "Field 'cmd3Offset' is not a number\n");
                }
            }
            else {
                syslog(LOG_WARNING, "Field 'cmd3Offset' not found\n");
            }

            /*
             *  Retrives the modbus slave address
             */
            int address = 0;
            const cJSON* jAddress = cJSON_GetObjectItemCaseSensitive(jsonModbus,"address");
            if (jAddress != NULL) {
                if (cJSON_IsNumber(jAddress)) {
                    address = jAddress->valueint;
                }
                else {
                    syslog(LOG_WARNING, "Field 'address' is not a number\n");
                }
            }
            else {
                syslog(LOG_WARNING, "Field 'address' not found\n");
            }

            /*
             *  Retrives the serverAddress
             */
            std::string serverAddress;
            const cJSON* jServerAddress = cJSON_GetObjectItemCaseSensitive(jsonModbus,"serverAddress");
            if (jServerAddress != NULL) {
                if (cJSON_IsString(jServerAddress)) {
                    serverAddress = jServerAddress->valuestring;
                }
                else {
                    syslog(LOG_WARNING, "Field 'serverAddress' is not a String\n");
                }
            }
            else {
                syslog(LOG_WARNING, "Field 'serverAddress' not found\n");
            }

            /*
             *  Retrives the serverPort
             */
            int serverPort = 1502;
            const cJSON* jServerPort = cJSON_GetObjectItemCaseSensitive(jsonModbus,"serverPort");
            if (jServerPort != NULL) {
                if (cJSON_IsNumber(jServerPort)) {
                    serverPort = jServerPort->valueint;
                }
                else {
                    syslog(LOG_WARNING, "Field 'serverPort' is not a number\n");
                }
            }
            else {
                syslog(LOG_WARNING, "Field 'serverPort' not found\n");
            }

            /*
             * Initializing the capture structure before filling with the register map
             */
            ModbusInfo *modbus = new ModbusInfo();
            modbus->cmd4Offset = cmd4Offset;
            modbus->cmd3Offset = cmd3Offset;
            modbus->address = address;
            modbus->serverAddress = serverAddress;
            modbus->serverPort = serverPort;
            
            const cJSON* jsonRegisters = cJSON_GetObjectItemCaseSensitive(jsonModbus,"registers");
            if (jsonRegisters != NULL) {
                cJSON* jsonRegister;
                /*
                 * Retrieve the slaves list
                 */
                cJSON_ArrayForEach(jsonRegister, jsonRegisters) {
                    int reg = -1;
                    const cJSON* jResgister = cJSON_GetObjectItemCaseSensitive(jsonRegister,"register");
                    if (jResgister != NULL) {
                        if (cJSON_IsNumber(jResgister)) {
                            reg = jResgister->valueint;
                        }
                        else {
                            syslog(LOG_WARNING, "Field 'register' is not a number\n");
                        }
                    }
                    else {
                        syslog(LOG_WARNING, "Field 'register' not found\n");
                        continue;
                    }
                    /*
                     * Type: default value: 0
                     */
                    int _type = 0;
                    const cJSON* jType = cJSON_GetObjectItemCaseSensitive(jsonRegister,"type");
                    if (jType != NULL) {
                        if (cJSON_IsNumber(jType)) {
                            _type = jType->valueint;
                        }
                        else {
                            syslog(LOG_WARNING, "Field 'type' is not a number\n");
                        }
                    }
                    else {
                        syslog(LOG_WARNING, "Field 'type' not found\n");
                    }
                    /*
                     * Name: default value: empty
                     */
                    const cJSON* jName = cJSON_GetObjectItemCaseSensitive(jsonRegister,"name");
                    std::string _name;
                    if (jName != NULL) {
                        if (cJSON_IsString(jName)) {
                            _name = jName->valuestring;
                        }
                        else {
                            syslog(LOG_WARNING, "Field 'name' is not a string\n");
                        }
                    }
                    else {
                        syslog(LOG_WARNING, "Field 'name' not found\n");
                    }
                    /*
                     * Command: default value: 4
                     */
                    int _command = 4;
                    const cJSON* jCommand = cJSON_GetObjectItemCaseSensitive(jsonRegister,"command");
                    if (jCommand != NULL) {
                        if (cJSON_IsNumber(jCommand)) {
                            _command = jCommand->valueint;
                        }
                        else {
                            syslog(LOG_WARNING, "Field 'command' is not a number\n");
                        }
                    }
                    else {
                        syslog(LOG_WARNING, "Field 'command' not found\n");
                    }
                    /*
                     * Add the item into the map only if there is a register
                     */
                    if (reg != -1) {
                        modbus->map[reg].type = _type;
                        modbus->map[reg].name = _name;
                        modbus->map[reg].command = _command;
                        syslog(LOG_INFO, "SlaveMap: adding register %d: name=%s,command=%d,type=%d\n",
                                reg, modbus->map[reg].name.c_str(), modbus->map[reg].command, modbus->map[reg].type);
                    }
                }
            }

            /*
             * Adding the structure to the main list
             */
            if (slave.capture != NULL) {
                delete slave.capture;
                slave.capture = NULL;
            }
            slave.capture = (CaptureInfo*)modbus;
        }
    }
    else {
        syslog(LOG_WARNING, "Field 'protocol' not found\n");
    }
}

void SlaveMap::extractCapture(int protocol, const cJSON* jsonCapture, SlaveInfo& slave) {
    /*
     * Continue the evaluation based on the protocol type
     */
    switch (protocol) {
    case CAPTURE_PROTOCOL_MODBUS_RTU:
    case CAPTURE_PROTOCOL_MODBUS_TCP:
        extractCaptureModbus(jsonCapture,slave);
        break;
    default:
        syslog(LOG_ERR, "Unknown protocol type: %d\n",protocol);
        break;
    }
    /*
     * If everything is fine, update the protocol configuration
     */
    if (slave.capture != NULL) {
        slave.capture->protocol = protocol;
    }
}

int SlaveMap::process(const cJSON *config) {

    /*
     * Clear current setup when loading a new one
     */
    slaves.clear();

    const cJSON* jsonSlaves = cJSON_GetObjectItemCaseSensitive(config,"addresses");
    if (jsonSlaves != NULL) {
        cJSON* jsonSlave;
        /*
         * Retrieve the slaves list
         */
        cJSON_ArrayForEach(jsonSlave, jsonSlaves) {
            SlaveInfo slave;
            /*
             *  Retrives the slave transmission object
             */
            const cJSON* jsonTransmission = cJSON_GetObjectItemCaseSensitive(jsonSlave,"transmission");
            if (jsonTransmission != NULL) {
                if (cJSON_IsObject(jsonTransmission)) {

                    /*
                     *  Retrives the protocol type
                     */
                    int protocol = -1;
                    const cJSON* jProtocol = cJSON_GetObjectItemCaseSensitive(jsonTransmission,"protocol");
                    if (jProtocol != NULL) {
                        if (cJSON_IsNumber(jProtocol)) {
                            protocol = jProtocol->valueint;
                        }
                        else {
                            syslog(LOG_WARNING, "Field 'protocol' is not a number\n");
                        }
                    }
                    else {
                        syslog(LOG_WARNING, "Field 'protocol' not found\n");
                    }

                    extractTransmission(protocol, jsonTransmission, slave);
                }
                else {
                    syslog(LOG_WARNING, "Field 'transmission' is not an object\n");
                }
            }

            /*
             *  Retrives the slave capture object
             */
            const cJSON* jsonCapture = cJSON_GetObjectItemCaseSensitive(jsonSlave,"capture");
            if (jsonCapture != NULL) {
                if (cJSON_IsObject(jsonCapture)) {

                    /*
                     *  Retrives the protocol
                     */
                    int protocol = -1;
                    const cJSON* jProtocol = cJSON_GetObjectItemCaseSensitive(jsonCapture,"protocol");
                    if (jProtocol != NULL) {
                        if (cJSON_IsNumber(jProtocol)) {
                            protocol = jProtocol->valueint;
                        }
                        else {
                            syslog(LOG_WARNING, "Field 'protocol' is not a number\n");
                        }
                    }
                    else {
                        syslog(LOG_WARNING, "Field 'protocol' not found\n");
                    }

                    extractCapture(protocol, jsonCapture, slave);
                }
            }

            slaves.push_back(slave);
        }
    }

    return 0;
}

int SlaveMap::save(void) {
    cJSON* jOutput = build();

    /*
     * Open file to save output
     */
    FILE *fp = NULL;
    fp = fopen(MODBUS_MAP,"w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Problem opening modbus map file for writing: %s\n", MODBUS_MAP);
        cJSON_Delete(jOutput);
        return -1;
    }
    
    /*
     * Generating the string and saving to the file
     */
    char *output = cJSON_PrintUnformatted(jOutput);
    size_t outLen = strlen(output);
    size_t nwrite = fwrite(output,1,outLen,fp);
    if (nwrite < 0) {
        syslog(LOG_ERR, "Problem writing modbus map file\n");
    }
    else if (nwrite != outLen) {
        syslog(LOG_WARNING, "Modbus map file not written completely\n");
    }

    /*
     * Finishing
     */
    fclose(fp);
    cJSON_Delete(jOutput);
    free(output);

    return 0;
}

cJSON* SlaveMap::build(void) {
    cJSON* jOutput = cJSON_CreateObject();
    if (jOutput == NULL) {
        syslog(LOG_ERR, "Memory problem during creating modbus map file\n");
        return NULL;
    }

    cJSON *jSlaves = cJSON_AddArrayToObject(jOutput,"addresses");

    for(const SlaveInfo& slave : slaves){
        /* Slave */
        cJSON* jSlave = cJSON_CreateObject();

        /* Transmission */
        cJSON* jTransmission = cJSON_CreateObject();

        cJSON_AddNumberToObject(jTransmission,"protocol",slave.transmission->protocol);
        cJSON_AddStringToObject(jTransmission,"hostAddress",((ProtocolMqttInfo*)slave.transmission)->hostAddress.c_str());
        cJSON_AddStringToObject(jTransmission,"port",((ProtocolMqttInfo*)slave.transmission)->port.c_str());
        cJSON_AddStringToObject(jTransmission,"username",((ProtocolMqttInfo*)slave.transmission)->username.c_str());
        cJSON_AddStringToObject(jTransmission,"password",((ProtocolMqttInfo*)slave.transmission)->password.c_str());
        cJSON_AddNumberToObject(jTransmission,"payloadType",((ProtocolMqttInfo*)slave.transmission)->payloadType);

        cJSON_AddItemToObject(jSlave, "transmission", jTransmission);

        /* Capture */
        cJSON* jCapture = cJSON_CreateObject();

        cJSON_AddNumberToObject(jCapture,"protocol",slave.capture->protocol);

        /* Modbus */
        cJSON* jModbus = cJSON_CreateObject();

        cJSON_AddNumberToObject(jModbus,"cmd4Offset",((ModbusInfo*)slave.capture)->cmd4Offset);
        cJSON_AddNumberToObject(jModbus,"cmd3Offset",((ModbusInfo*)slave.capture)->cmd3Offset);
        cJSON_AddNumberToObject(jModbus,"address",((ModbusInfo*)slave.capture)->address);
        cJSON_AddStringToObject(jModbus,"serverAddress",((ModbusInfo*)slave.capture)->serverAddress.c_str());
        cJSON_AddNumberToObject(jModbus,"serverPort",((ModbusInfo*)slave.capture)->serverPort);
        cJSON* jRegisters = cJSON_AddArrayToObject(jModbus,"registers");
        for (const auto& [address, mbRegister] : ((ModbusInfo*)slave.capture)->map) {
            cJSON* jRegister = cJSON_CreateObject();
            cJSON_AddNumberToObject(jRegister,"register",address);
            cJSON_AddNumberToObject(jRegister,"type",mbRegister.type);
            cJSON_AddStringToObject(jRegister,"name",mbRegister.name.c_str());
            cJSON_AddNumberToObject(jRegister,"command",mbRegister.command);
            cJSON_AddItemToArray(jRegisters, jRegister);
        }

        cJSON_AddItemToObject(jCapture,"modbus",jModbus);

        cJSON_AddItemToObject(jSlave,"capture",jCapture);

        cJSON_AddItemToArray(jSlaves,jSlave);
    }

    return jOutput;
}