#include "Transmission.h"
#include "defs.h"
#include "Payload.h"
#include "ModbusUtils.h"
#include "data/ModbusInfo.h"
#include "data/ProtocolMqttInfo.h"
#include "Utils.h"

#include <stdio.h>
#include <syslog.h>
#include <dirent.h>
#include <netutils/cJSON.h>

#define duration(a)       std::chrono::duration_cast<std::chrono::seconds>(a).count()
#define duration_msec(a)  std::chrono::duration_cast<std::chrono::milliseconds>(a).count()
#define timeNow()         std::chrono::system_clock::now()

Transmission::Transmission(SystemData *data, MqttClient *mqttClient, Leds *leds) : 
                _leds(leds), _data(data), _mqttClient(mqttClient) {
    sendTimer = timeNow();
}

void Transmission::run(void) {
    switch(state) {
        case STATE_IDLE:
            runIdleState();
            break;
        case STATE_CONNECTING:
            runConnectingState();
            break;
        case STATE_CONNECTED:
            runConnectedState();
            break;
    }
}

void Transmission::runIdleState(void) {
    if (_data == NULL) {
        syslog(LOG_ERR, "Transmission: 'data' structure not initialized\n");
        return;
    }
    switch(_data->cfg->transmissionMode) {
    case TRANSMISSION_MODE_CONNECTED:
        if (_mqttClient->isConnected() == false) {
            _mqttClient->start(_data->cfg);
            state = STATE_CONNECTING;
        }
        break;
    case TRANSMISSION_MODE_STANDARD:
        if ((int)duration(timeNow() - sendTimer) >= _data->cfg->sendInterval) {
            /* Reset the timer */
            sendTimer = timeNow();
            /* Start the connection */
            _mqttClient->start(_data->cfg);
            state = STATE_CONNECTING;
        }
        break;
    case TRANSMISSION_MODE_INDIVIDUAL:
        if ((int)duration(timeNow() - sendTimer) >= _data->cfg->sendInterval) {
            /*
             * Turn on the led
             */
            if (_leds != NULL) {
                _leds->on(Leds::TRANSMISSION);
            }
            /* Reset the timer */
            sendTimer = timeNow();
            /*
             * Start the transmission: Initilialize the structures
             * and change the state
             */
            slaveList.clear();
            slaveList = ModbusUtils::buildAddressList(_data->slaveMap->slaves);
            /*
             * Get the last slave from the list, removing it
             * from the list
             */
            currentSlave = slaveList.back();
            slaveList.pop_back();
            /* 
             * Build the file list for the first slave
             */
            buildFileList(currentSlave);
            syslog(LOG_DEBUG, "Transmission: Starting communication for slave %d\n",currentSlave);
            /* Start the connection */
            _mqttClient->connectToBroker(currentSlave,_data->slaveMap,_data->cfg);
            /*
             * Continue the transmission process only if connection was successfull
             */
            if (_mqttClient->isConnected() == true) {
                state = STATE_CONNECTING;
            }
        }
        break;
    }
}

void Transmission::runConnectingState(void) {
    if (_data == NULL) {
        syslog(LOG_ERR, "Transmission: 'data' structure not initialized\n");
        return;
    }

    switch(_data->cfg->transmissionMode) {
    case TRANSMISSION_MODE_CONNECTED:
        if (_mqttClient->isConnected() == true) {
            /*
             * Initialize the structures
             */
            slaveList.clear();
            fileList.clear();
            transmissionStarted = false;
            /*
             * Go to the next state
             */
            state = STATE_CONNECTED;
        }
        break;
    case TRANSMISSION_MODE_STANDARD:
        if (_mqttClient->isConnected() == true) {
            /*
             * Start the transmission: Initilialize the structures
             * and change the state
             */
            slaveList.clear();
            slaveList = ModbusUtils::buildAddressList(_data->slaveMap->slaves);
            /*
             * Get the last slave from the list, removing it
             * from the list
             */
            currentSlave = slaveList.back();
            slaveList.pop_back();
            /*
             * Go to the next state
             */
            state = STATE_CONNECTED;
        }
        break;
    case TRANSMISSION_MODE_INDIVIDUAL:
        /*
         * Go directly to the next state
         */
        state = STATE_CONNECTED;
        break;
    }
}

void Transmission::runConnectedState(void) {
    if (_data == NULL) {
        syslog(LOG_ERR, "Transmission: 'data' structure not initialized\n");
        return;
    }

    switch(_data->cfg->transmissionMode) {
    case TRANSMISSION_MODE_CONNECTED:
        if (_mqttClient->isConnected() == true) {
            if (transmissionStarted) {
                /*
                 * Check if the file list for the current slave is empty
                 */
                if (fileList.size() > 0) {
                    /*
                     * Extract the file from the list
                     */
                    std::string currentFile = fileList.back();
                    fileList.pop_back();
                    // syslog(LOG_DEBUG, "Transmission: Sending file %s for slave %d\n",currentFile.c_str(), currentSlave);
                    /*
                     * Send the file and remove it from the disk, in 
                     * case of success
                     */
                    buildSend(currentSlave,currentFile);
                    /*
                     * Toggle transmission led, to indicate activity
                     */
                    if (_leds != NULL) {
                        _leds->toggle(Leds::TRANSMISSION);
                    }
                }
                else {
                    if (slaveList.size() > 0) {
                        /*
                         * Get the next slave
                         */
                        currentSlave = slaveList.back();
                        slaveList.pop_back();
                        /* 
                         * Build the file list for the first slave
                         */
                        buildFileList(currentSlave);
                    }
                    else {
                        transmissionStarted = false;
                        syslog(LOG_ERR, "Transmission: End of transmission\n");
                        /*
                         * Indicate transmission end led
                         */
                        if (_leds != NULL) {
                            _leds->off(Leds::TRANSMISSION);
                        }
                    }
                }
            }
            else {
                /*
                 * Check the timer
                 */
                if ((int)duration(timeNow() - sendTimer) >= _data->cfg->sendInterval) {
                    /*
                     * Turn on the led
                     */
                    if (_leds != NULL) {
                        _leds->on(Leds::TRANSMISSION);
                    }
                    /* Reset the timer */
                    sendTimer = timeNow();
                    /*
                     * Start the transmission: Initilialize the structures
                     * and change the state
                     */
                    slaveList.clear();
                    slaveList = ModbusUtils::buildAddressList(_data->slaveMap->slaves);
                    /*
                     * Get the last slave from the list, removing it
                     * from the list
                     */
                    currentSlave = slaveList.back();
                    slaveList.pop_back();
                    /* 
                     * Build the file list for the first slave
                     */
                    buildFileList(currentSlave);
                    /*
                     * Start sending the files
                     */
                    transmissionStarted = true;
                    /*
                     * Indicate transmission start led
                     */
                    if (_leds != NULL) {
                        _leds->on(Leds::TRANSMISSION);
                    }
                }
            }
        }
        else {
            /* 
             * Not connected. Goes to the correct state, to request
             * reconnection.
             */
            state = STATE_IDLE;
        }
        break;
    case TRANSMISSION_MODE_STANDARD:
        /* For now, do nothing */
        syslog(LOG_WARNING,"Transmission: Mode not supported\n");
        /*
         * Go back to the initial state
         */
        state = STATE_IDLE;
        break;
    case TRANSMISSION_MODE_INDIVIDUAL:
        if (fileList.size() > 0) {
            /*
             * Extract the file from the list
             */
            std::string currentFile = fileList.back();
            fileList.pop_back();
            // syslog(LOG_DEBUG, "Transmission: Sending file %s for slave %d\n",currentFile.c_str(), currentSlave);
            /*
             * Send the file and remove it from the disk, in 
             * case of success
             */
            buildSend(currentSlave,currentFile);
            /*
             * Toggle transmission led, to indicate activity
             */
            if (_leds != NULL) {
                _leds->toggle(Leds::TRANSMISSION);
            }
        }
        else {
            /* 
             * Stop MQTT connection 
             */
            _mqttClient->stop();
            /*
             * End file list, go to the next slave. Or end the transmission, if there is
             * no more slaves in the list
             */
            if (slaveList.size() > 0) {
                /* 
                 * Get the new slave from the list and build a new file list to be sent
                 */
                currentSlave = slaveList.back();
                slaveList.pop_back();
                buildFileList(currentSlave);
                /* 
                 * Connect to the new broker configured for this slave 
                 */
                _mqttClient->connectToBroker(currentSlave,_data->slaveMap,_data->cfg);
                /*
                 * Toggle transmission led, to indicate activity
                 */
                if (_leds != NULL) {
                    _leds->toggle(Leds::TRANSMISSION);
                }
            }
            else {
                /* End of transmission */
                syslog(LOG_INFO, "Transmission: End of transmission\n");
                /*
                 * Turn off the led, indicating end of transmission
                 */
                if (_leds != NULL) {
                    _leds->off(Leds::TRANSMISSION);
                }
                /*
                 * Go back to the initial state
                 */
                state = STATE_IDLE;
            }
        }
        break;
    }    
}

void Transmission::buildSend(int slave, std::string filepath) {
    /*
     * Open the input file
     */
    FILE* fp = fopen(filepath.c_str(),"r");
    if (fp == NULL) {
        syslog(LOG_ERR, "Transmission: problem opening file %s\n", filepath.c_str());
        return;
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
        syslog(LOG_ERR, "Transmission: Problem initializing memory for reading configuration file: %s\n", filepath.c_str());
        fclose(fp);
        return;
    }
    memset(data,0,len+1);
    /*
     * Read file content
     */
    int nread = fread(data,1,len,fp);
    if (nread != len) {
        syslog(LOG_ERR, "Transmission: Problem reading configuration file: %s\n", filepath.c_str());
        free(data);
        fclose(fp);
        return;
    }
    /*
     * Get the payload type to be used
     */
    int payloadType = -1;
    if (_data->cfg->transmissionMode == TRANSMISSION_MODE_INDIVIDUAL) {
        bool found = false;
        for (const auto& _slave : _data->slaveMap->slaves) {
            ModbusInfo *modbus = (ModbusInfo*)_slave.capture;
            if (modbus->address == slave) {
                /* Found the slave in list. Get the transmission type */
                ProtocolMqttInfo *mqtt = (ProtocolMqttInfo*)_slave.transmission;
                found = true;
                payloadType = mqtt->payloadType;                
            }
        }
        /* Check if the slave is found */
        if (found == false) {
            syslog(LOG_ERR, "Transmission: Slave not found to build payload\n");
            free(data);
            fclose(fp);
            return;
        }
    }
    else {
        payloadType = _data->cfg->payloadType;
    }
    // syslog(LOG_DEBUG,"Transmission: sending data with payload type %s\n", Utils::PayloadType(payloadType).c_str());
    /*
     * Build the output JSON structure, according to the payload type
     */
    cJSON* payload;
    switch (payloadType)
    {
    case PAYLOAD_TYPE_STD:
        payload = Payload::buildStandard(_data->cfg->deviceId, slave, data, _data->slaveMap);
        break;
    case PAYLOAD_TYPE_KRON:
        payload = Payload::buildKron(slave, data, _data->slaveMap);
        break;
    default:
        syslog(LOG_ERR,"Transmission: Invalid payload type: %d\n",payloadType);
        free(data);
        fclose(fp);
        return;
        break;
    }
    /* Check if the payload was built successfully */
    if (payload == NULL) {
        syslog(LOG_ERR, "Transmission: problem generating payload output for file %s\n", filepath.c_str());
        free(data);
        fclose(fp);
        return;
    }
    /*
     * Generate the output string and send
     */
    char *output = cJSON_PrintUnformatted(payload);
    std::string outputStr = output;
    if (_mqttClient->publish(_data->cfg->mqtt.pubTopic, outputStr) == 0) {
        /*
         * Publish success ... removing the file
         */
        unlink(filepath.c_str());
        syslog(LOG_DEBUG, "Transmission: Publish success. File %s removed\n", filepath.c_str());
    }
    else {
        /*
         * Force stop mqtt connection
         */
        _mqttClient->stop();
    }
    /*
     * Free the memory
     */
    free(data);
    fclose(fp);
    cJSON_Delete(payload);
    free(output);    
}

void Transmission::buildFileList(int slave) {
    /*
     * Clear the current list
     */
    fileList.clear();
    /*
     * Open the root directory
     */
    DIR *pDir = opendir(FILEPATH);
    if (pDir == NULL) {
        syslog(LOG_ERR, "Transmission: Cannot open directory %s\n", FILEPATH);
        return;
    }

    /*
     * Scan files
     */
    struct dirent *pDirent;
    while ((pDirent = readdir(pDir)) != NULL) {
        int slaveNb = -1;
        int counter = -1;
        int ret = sscanf(pDirent->d_name,"%dT%d",&slaveNb, &counter);
        /*
         * Result checks
         */
        if (ret != 2) {
            continue;
        }
        if ((slaveNb == -1) || (counter == -1)) {
            continue;
        }
        if (ModbusUtils::hasSlaveAddress(_data->slaveMap->slaves,slaveNb) == false) {
            syslog(LOG_WARNING, "Transmission: File %s associated to invalid slave number %d. Removing.\n", pDirent->d_name, slaveNb);
            std::string fileToRemove = FILEPATH;
            fileToRemove += pDirent->d_name;
            unlink(fileToRemove.c_str());
            continue;
        }
        if (slaveNb == slave) {
            /*
             * Add the file to the list, includind the path
             */
            std::string filename = FILEPATH;
            filename += "/";
            filename += pDirent->d_name;
            fileList.push_back(filename);
        }
    }

    /*
     * Close the directory
     */
    closedir(pDir);
}
