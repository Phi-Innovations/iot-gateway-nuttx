#include "Manager.h"

#include <string>

#include <sys/boardctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <nuttx/usb/usbdev.h>
#include <nuttx/usb/cdcacm.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <syslog.h>

Manager::Manager(SystemData *_data, Status *_status) : data(_data), status(_status) {
    /*
     * Create Events objects
     */
    configCmd = new ConfigCommand();
    mqttCmd = new MqttCommand();
    ethCmd = new EthernetCommand();
    wifiCmd = new WifiCommand();
    gsmCmd = new GsmCommand();
    modbusCmd = new ModbusCommand();
    datetimeCmd = new DatetimeCommand();
    deviceidCmd = new DeviceIdCommand();
    operationCmd = new OperationCommand();
    scanCmd = new ScanGeneralCommand();
    scanMapCmd = new ScanMapCommand();
    certCmd = new CertCommand();
    systemCmd = new SystemCommand();
    updateCmd = new UpdateCommand();
    statusCmd = new StatusCommand();
    modbusReadCmd = new ModbusReadCommand();
    modbusWriteCmd = new ModbusWriteCommand();

    /*
     * Register the commands
     */
    map["config"] = configCmd;
    map["config"]->isStringPayload = true;
    map["mqtt"] = mqttCmd;
    map["ethernet"] = ethCmd;
    map["wifi"] = wifiCmd;
    map["gsm"] = gsmCmd;
    map["modbus"] = modbusCmd;
    map["datetime"] = datetimeCmd;
    map["datetime"]->isStringPayload = true;
    map["deviceid"] = deviceidCmd;
    map["operation"] = operationCmd;
    map["scanGeneral"] = scanCmd;
    map["scanMap"] = scanMapCmd;
    map["cert"] = certCmd;
    map["cert"]->isStringPayload = true;
    map["system"] = systemCmd;
    map["system"]->isStringPayload = true;
    map["update"] = updateCmd;
    map["status"] = statusCmd;
    map["modbus_read"] = modbusReadCmd;
    map["modbus_write"] = modbusWriteCmd;

    /*
     * Initialize USB CDC handler
     * The startUSB might be used later
     */
    g_cdcacm.handle = NULL;

    startUSB();
}

Manager::~Manager() {
    // if (configCmd != NULL) {
    //     delete configCmd;
    // }
    // if (mqttCmd != NULL) {
    //     delete mqttCmd;
    // }
    // if (ethCmd != NULL) {
    //     delete ethCmd;
    // }
    // if (wifiCmd != NULL) {
    //     delete wifiCmd;
    // }
    // if (gsmCmd != NULL) {
    //     delete gsmCmd;
    // }
    // if (modbusCmd != NULL) {
    //     delete modbusCmd;
    // }
    // if (datetimeCmd != NULL) {
    //     delete datetimeCmd;
    // }
    // if (deviceidCmd != NULL) {
    //     delete deviceidCmd;
    // }
    // if (scanCmd != NULL) {
    //     delete scanCmd;
    // }
    // if (scanMapCmd != NULL) {
    //     delete scanMapCmd;
    // }
    // if (certCmd != NULL) {
    //     delete certCmd;
    // }
    // if (systemCmd != NULL) {
    //     delete systemCmd;
    // }
    // if (updateCmd != NULL) {
    //     delete updateCmd;
    // }
    // if (statusCmd != NULL) {
    //     delete statusCmd;
    // }
    // if (modbusReadCmd != NULL) {
    //     delete modbusReadCmd;
    // }
    // if (modbusWriteCmd != NULL) {
    //     delete modbusWriteCmd;
    // }

    stopUSB();
}

int Manager::startUSB(void) {
    struct boardioc_usbdev_ctrl_s ctrl;
    int ret;

    /* Check if there is a non-NULL USB mass storage device handle (meaning that the
    * USB mass storage device is already configured).
    */

    if (g_cdcacm.handle) {
        syslog(LOG_WARNING, "Manager: USB Device already connected\n");
        return -1;
    }

    /* Then, in any event, enable trace data collection as configured BEFORE
    * enabling the CDC/ACM device.
    */

    usbtrace_enable(TRACE_BITSET);

    /* Initialize the USB CDC/ACM serial driver */

    syslog(LOG_DEBUG, "Manager: USB Device: Registering CDC/ACM serial driver\n");

    ctrl.usbdev   = BOARDIOC_USBDEV_CDCACM;
    ctrl.action   = BOARDIOC_USBDEV_CONNECT;
    ctrl.instance = CONFIG_SYSTEM_CDCACM_DEVMINOR;
    ctrl.handle   = &g_cdcacm.handle;

    ret = boardctl(BOARDIOC_USBDEV_CONTROL, (uintptr_t)&ctrl);
    if (ret < 0) {
        syslog(LOG_ERR, "Manager: USB Device: Failed to create the CDC/ACM serial device: %d\n",-ret);
        return -1;
    }

    syslog(LOG_INFO, "Manager: Successfully registered the CDC/ACM serial driver\n");

    return 0;
}

int Manager::stopUSB(void) {
    struct boardioc_usbdev_ctrl_s ctrl;
    
    /* First check if the USB mass storage device is already connected */
    if (!g_cdcacm.handle) {
        syslog(LOG_WARNING, "Manager: USB Device: ERROR: Not connected\n");
        return -1;
    }

    /* Then, in any event, disable trace data collection as configured BEFORE
     * enabling the CDC/ACM device.
     */
    usbtrace_enable(0);

    /* Then disconnect the device and uninitialize the USB mass storage driver */
    ctrl.usbdev   = BOARDIOC_USBDEV_CDCACM;
    ctrl.action   = BOARDIOC_USBDEV_DISCONNECT;
    ctrl.instance = CONFIG_SYSTEM_CDCACM_DEVMINOR;
    ctrl.handle   = &g_cdcacm.handle;

    boardctl(BOARDIOC_USBDEV_CONTROL, (uintptr_t)&ctrl);
    g_cdcacm.handle = NULL;
    syslog(LOG_INFO, "Manager: USB Device: Disconnected\n");
    return 0;
}

void Manager::run(void) {
    fd_set rfds;
    struct timeval  tv;

    tv.tv_sec = 0;
    tv.tv_usec = 5000;
    FD_ZERO(&rfds);
    FD_SET(usbFD, &rfds);

    switch(state) {
        case STARTING:
            usbFD = open("/dev/ttyACM0", O_RDWR);
            if (usbFD < 0) {
                //syslog(LOG_ERR, "USB open failed: %d\n", errno);
            }
            else {
                /*
                 * Success: change state
                 */
                syslog(LOG_INFO, "USB connected\n");
                state = RUNNING;
            }
            break;
        case RUNNING:
            if (select(usbFD + 1, &rfds, NULL, NULL, &tv) == -1) {
                if (errno != EINTR) {
                    syslog(LOG_ERR, "Problem with usb select(): %d\n", errno);
                    /* TODO: find out how to proceed in this case */
                }
                syslog(LOG_ERR, "select() -1\n");
            }
            else if (FD_ISSET(usbFD, &rfds)) {
                memset(rxBuf,0,sizeof(rxBuf));
                int bytesRead = read(usbFD, rxBuf, sizeof(rxBuf));
                if (bytesRead == -1) {
                    syslog(LOG_WARNING, "USB disconnected\n");
                    close(usbFD);
                    state = STARTING;
                }
                else {
                    /* Evaluate the arrived message */
                    processRxBuffer(bytesRead);
                }
            }
            break;
    }

    /*
     * Evaluate message in case of new message arrival
     */
    if (newMessage) {
        newMessage = false;
        cJSON* output = evaluateMessage();
        if (output != NULL) {
            if (sendResponse(usbFD,output) < 0) {
                syslog(LOG_ERR, "Problem sending 'scanGeneral' command response\n");
            }
            /*
             * Free the cJSON structure created here
             * the input structure must be freed in Manager
             */
            cJSON_free(output);
        }
    }
}

void Manager::processRxBuffer(int nbBytes) {
    /*
     * Scan the rxBuf for each byte, processing the 
     * receiving data
     */
    for (int i=0;i<nbBytes;i++) {
        switch (msgState) {
            case WAITING:
                if (rxBuf[i] == STX) {
                    printf("S");
                    memset(msgBuf,0,sizeof(msgBuf));
                    msgBufPos = 0;
                    msgState = RECEIVING;
                }
                break;
            case RECEIVING:
                if (rxBuf[i] == ETX) {
                    printf("E\n");
                    /*
                     * End the message. Notify arrival
                     */
                    newMessage = true;
                    msgState = WAITING;
                }
                else {
                    printf(".");
                    /*
                     * Add content to message buffer
                     */
                    msgBuf[msgBufPos] = rxBuf[i];
                    msgBufPos++;
                }
                break;
        }
    }
}

bool Manager::isValidTopic(const std::string& topic) {
    if (topic == data->cfg->mqtt.cmdTopic) {
        return true;
    }
    return false;
}

cJSON* Manager::evaluateMessage(char *msg, size_t len) {
    /*
     * Transfer data from external buffer to internal buffer for
     * evaluation
     */
    memset(msgBuf,0,sizeof(msgBuf));
    memcpy(msgBuf,msg,len);
    /*
     * Evaluate
     */
    return evaluateMessage();
}

cJSON* Manager::evaluateMessage(std::string msg) {
    /*
     * Transfer data from external buffer to internal buffer for
     * evaluation
     */
    memset(msgBuf,0,sizeof(msgBuf));
    memcpy(msgBuf,msg.c_str(),msg.size());
    /*
     * Evaluate
     */
    return evaluateMessage();
}

cJSON* Manager::evaluateMessage(void) {
    cJSON* output = NULL;
    /*
     * Parse the JSON command
     */
    cJSON *jData = cJSON_Parse(msgBuf);
	if (jData == NULL) {
		syslog(LOG_ERR, "Problem parsing received message\n");
		return output;
	}

    /*
     * Every json is an object with 3 fields:
     * - command
     * - deviceId
     * - value
     * In this function we will check the if these fields are
     * available and also verify the device ID. Then, the command
     * will be evaluated.
     */
    std::string command;
    const cJSON* jCommand = cJSON_GetObjectItemCaseSensitive(jData,"command");
    if (jCommand == NULL) {
        syslog(LOG_ERR, "Message does not contain 'command' field\n");
        cJSON_Delete(jData);
        return output;
    }
	if (cJSON_IsString(jCommand)) {
        command = jCommand->valuestring;
    }
    else {
        syslog(LOG_ERR, "Message 'command' field is not a string\n");
        cJSON_Delete(jData);
        return output;
    }
    syslog(LOG_DEBUG, "Command identified: %s\n",command.c_str());

    int deviceId;
    const cJSON* jDeviceId = cJSON_GetObjectItemCaseSensitive(jData,"deviceId");
    if (jDeviceId == NULL) {
        syslog(LOG_ERR, "Message does not contain 'deviceId' field\n");
        cJSON_Delete(jData);
        return output;
    }
	if (cJSON_IsNumber(jDeviceId)) {
        deviceId = jDeviceId->valueint;
    }
    else {
        syslog(LOG_ERR, "Message 'deviceId' field is not an int\n");
        cJSON_Delete(jData);
        return output;
    }

    /*
     * Check the device Id
     */
    if (deviceId != data->cfg->deviceId) {
        syslog(LOG_WARNING, "Message sent with an invalid deviceId: %d / %d\n", deviceId, data->cfg->deviceId);
        cJSON_Delete(jData);
        return output;
    }

    const cJSON* jValue = cJSON_GetObjectItemCaseSensitive(jData,"value");
    if (jValue == NULL) {
        syslog(LOG_WARNING, "Field 'value' not found in %s command",command.c_str());
        cJSON_Delete(jData);
        return output;
    }

    /*
     * Execute the command
     */
    if (map.find(command) != map.end()) {
        /*
         * In case of some command, the value content is a string with
         * which parameter we want to capture. It must be extracted and 
         * passed as a parameter to the execute function
         */
        if (map[command] != NULL) {
            if (map[command]->isStringPayload == true) {
                if (cJSON_IsString(jValue)) {
                    std::string cmd = jValue->valuestring;
                    output = map[command]->execute(cmd,data);
                }
                else {
                    syslog(LOG_WARNING, "Command '%s', field 'value' is not a string", command.c_str());
                }
            }
            else {
                if (command == "status") {
                    /*
                     * Command 'status' is a special case, where the input to the event handler is
                     * the status structure
                     */
                    output = map[command]->execute(status,data);
                }
                else if (command == "update") {
                    updateMode = ((UpdateCommand*)map[command])->updateMode;
                }
                else {
                    output = map[command]->execute(jValue,data);
                }
            }
        }
    }
    else {
        syslog(LOG_WARNING, "Command not found\n");
    }

    cJSON_Delete(jData);

    return output;
}

int Manager::sendResponse(int fd, const cJSON *output) {

    if (fd < 0) {
        syslog(LOG_ERR, "Invalid descriptor for sending command response\n");
        return -1;
    }

    char *resp = cJSON_PrintUnformatted(output);
    /*
     * The response message must include the delimiters
     */
    int respLen = strlen(resp) + 3;
    char *finalResp = (char*)malloc(respLen);
    if (finalResp == NULL) {
        syslog(LOG_ERR, "Problem allocating memory for command response\n");
        return -1;
    }
    memset(finalResp,0,respLen);

    /* Adjust the length for data transfer */
    respLen -= 3;

    finalResp[0] = STX;
    memcpy(&finalResp[1],resp,respLen);
    finalResp[respLen+1] = ETX;

    /* Adjust the length for final transfer. The string '\0' terminator is not needed */
    respLen += 2;

    /*
     * Send the response
     */
    ssize_t nbBytes = write(fd, finalResp, respLen);
    if (nbBytes < 0) {
        syslog(LOG_ERR, "Problem sending command response: %d\n", errno);
    }

    /*
     * Freeing memory
     */
    free(resp);
    free(finalResp);

    return (nbBytes < 0) ? -1 : 0;
}

std::string Manager::getRespTopic(void) {
    return data->cfg->mqtt.rspTopic;
}

void Manager::addMqttCommand(std::string cmd) {
    if (mqttCmdList.size() == 5) {
        syslog(LOG_ERR,"Manager: MQTT command list full\n");
        return;
    }

    mqttCmdList.push(cmd);
}

std::string Manager::getMqttCommand(void) {
    std::string output;

    if (mqttCmdList.empty()) {
        return output;
    }

    output = mqttCmdList.front();
    mqttCmdList.pop();

    return output;
}
