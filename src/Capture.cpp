#include "Capture.h"
#include "defs.h"
#include "data/ModbusInfo.h"
#include "ModbusUtils.h"

#include <debug.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <dirent.h>

#include <nuttx/net/arp.h>
#include "netutils/netlib.h"
#include "netutils/dhcpc.h"

#define MODBUS_SEND     0
#define MODBUS_RECEIVE  1

#define duration(a)       std::chrono::duration_cast<std::chrono::seconds>(a).count()
#define timeNow()         std::chrono::system_clock::now()

Capture::Capture(SystemData *data, Leds *leds, Status *status) {
    _leds = leds;
    _status = status;

    if (data->cfg == NULL) {
        syslog(LOG_ERR, "Capture: Configuration not initialized\n");
        return;
    }

    if (data->slaveMap == NULL) {
        syslog(LOG_ERR, "Capture: Modbus map not initialized\n");
        return;
    }

    if (data->cfg->operationMode == GW_FUNCTION_MODBUS_GATEWAY) {
        initSlave();

        if (query == NULL) {
            syslog(LOG_ERR, "Capture: Cannot start Capture component\n");    
            return;
        }
    }

    /*
     * Check if the disk is full. For now, the chosen approach is limit the amount of
     * registers saved in disk. An improvement to get the total disk size must be
     * implemented
     */
    if (getNbRegisters() > MAX_NB_LOG_FILES) {
        syslog(LOG_WARNING, "Capture: Log disk FULL!\n");
    }

    ctx = modbus_new_rtu("/dev/ttyS2",data->cfg->modbus.baudrate,data->cfg->modbus.parity,
                            data->cfg->modbus.dataBit,data->cfg->modbus.stopBits);
    if (ctx == NULL) {
        syslog(LOG_ERR, "Capture: Error initializing modbus structure\n");
        state = ERROR;
        return;
    }

    modbus_set_response_timeout(ctx,5,0);
	modbus_set_indication_timeout(ctx,3,0);

    /* TODO: Define as a parameter */
    modbus_set_debug(ctx,0);

    if (data->cfg->operationMode == GW_FUNCTION_MODBUS_GATEWAY) {
        modbus_set_slave(ctx,data->cfg->modbus.slaveAddr);
    }

    if (modbus_connect(ctx) == -1) {
        syslog(LOG_ERR, "Capture: Problem connecting modbus\n");
        modbus_free(ctx);
        state = ERROR;
        return;
    }

    if (data->cfg->operationMode == GW_FUNCTION_MODBUS_GATEWAY) {
        header_length = modbus_get_header_length(ctx);
        syslog(LOG_DEBUG, "Capture: Setting header length = %d\n", header_length);
    }
    
    /*
     * Initialize the file position index structure
     */
    initializeFileIndex(data->slaveMap);

    /*
     * Start the timer and set initial state
     */
    scanTimer = timeNow();
    state = WAITING;

    syslog(LOG_INFO, "Capture: Component initialized\n");
}

Capture::~Capture() {
    if (query != NULL) {
        free(query);
    }
}

void Capture::initializeFileIndex(SlaveMap *map) {
    /*
     * Open the root directory
     */
    DIR *pDir = opendir(FILEPATH);
    if (pDir == NULL) {
        syslog(LOG_ERR, "Capture: Cannot open directory %s\n", FILEPATH);
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
        // syslog(LOG_DEBUG,"Analysing file %s: slaveNb=%d, counter=%d, ret=%d\n",pDirent->d_name, slaveNb,counter,ret);
        /*
         * Check scanf results
         */
        if (ret != 2) {
            continue;
        }
        if ((slaveNb == -1) || (counter == -1)) {
            continue;
        }
        /*
         * Search for the slave position in the modbus map list
         */
        bool found = false;
        for (auto& slave : map->slaves) {
            ModbusInfo* modbus = (ModbusInfo*)slave.capture;
            if (modbus->address == slaveNb) {
                if (counter > modbus->filePos) {
                    modbus->filePos = counter;
                }
                found = true;
            }
        }
        if (found == false) {
            syslog(LOG_ERR, "Capture: Could not find slave number %d in map\n",slaveNb);
        }
    }

    /*
     * Close the directory
     */
    closedir(pDir);
}

int Capture::scan(SystemData *data) {
    int waitingTime = 0;

    if (data->cfg->operationMode == GW_FUNCTION_MODBUS_DATALOGGER) {
        switch(state) {
            case WAITING:
                waitingTime = (int)duration(timeNow() - scanTimer);
                // syslog(LOG_DEBUG, "Capture: waiting %d / %d\n",waitingTime,data->cfg->scanInterval);
                if (waitingTime >= data->cfg->scanInterval) {
                    /*
                     * Reset the timer
                     */
                    scanTimer = timeNow();
                    /*
                     * Start the scan: Initilialize the structures
                     * and change the state
                     */
                    slaveList.clear();
                    slaveList = ModbusUtils::buildAddressList(data->slaveMap->slaves);
                    /*
                     * Get the last slave from the list, removing it
                     * from the list
                     */
                    currentSlave = slaveList.back();
                    slaveList.pop_back();
                    modbus_set_slave(ctx,currentSlave);
                    syslog(LOG_DEBUG,"Capture: Starting scan with slave %d\n",currentSlave);
                    /*
                     * Fill the register list with the contents from the
                     * initialized slave
                     */
                    registerList.clear();
                    registerList = ModbusUtils::buildRegisterList(data->slaveMap->slaves, currentSlave);
                    syslog(LOG_DEBUG, "Capture: Number of registers to read: %d\n",registerList.size());
                    /*
                     * Ready to start scanning
                     */
                    state = SCANNING;
                }
                break;
            case SCANNING:
                /*
                 * Toggle the led during scan
                 */
                if (_leds != NULL) {
                    _leds->toggle(Leds::MODBUS);
                }
                /*
                 * Every cycle it will be scanned one register at a time
                 */
                if (registerList.size() > 0) {
                    /*
                     * Get a register to scan
                     */
                    int reg = registerList.back();
                    registerList.pop_back();
                    syslog(LOG_DEBUG, "Capture: Scanning register %d from slave %d\n",reg, currentSlave);
                    /*
                     * Run MODBUS command, saving the result in the map
                     */
                    if (readRegister(data->slaveMap, currentSlave,reg) < 0) {
                        syslog(LOG_ERR, "Capture: Problem in reading modbus from slave %d. Discarding ...\n", currentSlave);
                        /*
                         * Go to the next
                         */
                        if (slaveList.size() > 0) {
                            /*
                             * Set the new slave
                             */
                            currentSlave = slaveList.back();
                            slaveList.pop_back();
                            modbus_set_slave(ctx,currentSlave);
                            /*
                             * Fill the register list with the contents from the
                             * new slave
                             */
                            registerList.clear();
                            registerList = ModbusUtils::buildRegisterList(data->slaveMap->slaves, currentSlave);
                            syslog(LOG_DEBUG, "Capture: Slave %d defined\n",currentSlave);
                        }
                        else {
                            state = WAITING;
                            syslog(LOG_DEBUG, "Capture: End of scan\n");
                        }
                    }
                }
                else {
                    /*
                     * End of scan for this slave.
                     * Save scanned data into a file. The value
                     * in the structure will be converted to a
                     * json file.
                     */
                    if (diskFull == false) {
                        save(data->slaveMap, currentSlave);
                    }
                    /*
                     * Go to the next one or end the procedure
                     */
                    syslog(LOG_DEBUG, "Capture: Slave list size = %d\n", slaveList.size());
                    if (slaveList.size() > 0) {
                        /*
                         * Set the new slave
                         */
                        currentSlave = slaveList.back();
                        slaveList.pop_back();
                        modbus_set_slave(ctx,currentSlave);
                        /*
                         * Fill the register list with the contents from the
                         * new slave
                         */
                        registerList.clear();
                        registerList = ModbusUtils::buildRegisterList(data->slaveMap->slaves, currentSlave);
                        syslog(LOG_DEBUG, "Capture: Slave %d defined\n",currentSlave);
                    }
                    else {
                        state = WAITING;
                        syslog(LOG_DEBUG, "Capture: End of scan\n");
                        /*
                         * Turn off the led
                         */
                        if (_leds != NULL) {
                            _leds->off(Leds::MODBUS);
                        }
                    }
                }
                break;
            case ERROR:
                break;
        }
    }
    else if (data->cfg->operationMode == GW_FUNCTION_MODBUS_GATEWAY) {
        union int16_v {
            uint16_t val;
            uint8_t  val8[2];
        };
        union int16_v reqAddress;
        /*
         * In case of problems in initialization, discard
         * the execution
         */
        if (query == NULL) {
            return -1;
        }
        /*
         * First check the received modbus message
         */
        int rc = modbus_receive(ctx, query);
        if (rc > 0) {
            int requestedSlave = query[0];
            int requestedCommand = query[1];
            reqAddress.val8[0] = query[3];
            reqAddress.val8[1] = query[2];

            /*
             * Validate the command and adjust the address based on the offset
             */
            int address = reqAddress.val;
            /*
             * Check if is a valid requested address before allowing the change in the value
             */
            if (isValidRequest(data->slaveMap, requestedSlave, address, requestedCommand) == true) {
                /*
                 * Search for the slave in list
                 */
                bool found = false;
                for (const auto& slave : data->slaveMap->slaves) {
                    ModbusInfo* modbus = (ModbusInfo*)slave.capture;
                    if (modbus->address == requestedSlave) {
                        found = true;
                        /*
                         * Slave found: process modbus response
                         */
                        rc = modbus_reply_val(ctx,query,rc,modbus->map[address].value);
                        /*
                         * Show the value: debugging only
                         */
                        // syslog(LOG_DEBUG,"Capture: Modbus response: Slave=%d,Command=%d,Address=%d,Value=%d %d %d %d\n", 
                        //             requestedSlave,requestedCommand,address,modbus->map[address].value[0],
                        //             modbus->map[address].value[1],modbus->map[address].value[2], modbus->map[address].value[3]);
                        /*
                         * End the loop
                         */
                        break;
                    }
                }
                /*
                 * Not found
                 */
                if (found == false) {
                    rc = modbus_reply_exception(ctx,query,MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS);
                }

            }
            else {
                rc = modbus_reply_exception(ctx,query,MODBUS_EXCEPTION_ILLEGAL_FUNCTION);
            }
            /*
             * Toggle modbus led, to indicate modbus operation
             */
            if (_leds != NULL) {
                _leds->toggle(Leds::MODBUS);
            }
        }
        /*
         * Second: Check if it is time to save data
         */
        waitingTime = (int)duration(timeNow() - scanTimer);
        // syslog(LOG_DEBUG, "Capture: waiting %d / %d\n",waitingTime,data->cfg->scanInterval);
        if (waitingTime >= data->cfg->scanInterval) {
            /* 
             * Reset the timer
             */
            scanTimer = timeNow();
            /*
             * Save the current values on a file
             */
            if (diskFull == false) {
                save(data->slaveMap, data->cfg->modbus.slaveAddr);
            }
        }
    }

    return 0;
}

int Capture::readRegister(SlaveMap *map, int slaveNb, int regNumber) {
    int regLen = 0;
    /*
     * Search for the slave
     */
    ModbusInfo* modbus = NULL;
    for (const auto& slave : map->slaves) {
        modbus = (ModbusInfo*)slave.capture;
        if ((modbus != NULL) && (modbus->address == slaveNb)) {
            /* Found. End the loop */
            break;
        }
        else {
            modbus = NULL;
        }
    }
    if (modbus == NULL) {
        syslog(LOG_ERR,"Capture: Slave not found in list: %d\n", slaveNb);
        return -1;
    }
    /*
     * Evaluating the register type
     */
    switch(modbus->map[regNumber].type) {
        case MODBUS_TYPE_UINT16:
            regLen = 1;
            break;
        case MODBUS_TYPE_UINT32:
            regLen = 2;
            break;
        case MODBUS_TYPE_FLOAT:
            regLen = 2;
            break;
        case MODBUS_TYPE_FLOAT_ABCD:
            regLen = 2;
            break;
        case MODBUS_TYPE_FLOAT_DCBA:
            regLen = 2;
            break;
        case MODBUS_TYPE_FLOAT_BADC:
            regLen = 2;
            break;
        case MODBUS_TYPE_FLOAT_CDAB:
            regLen = 2;
            break;
        case MODBUS_TYPE_DOUBLE:
            regLen = 4;
            break;
        default:
            syslog(LOG_ERR, "Unknown register type: %d\n", modbus->map[regNumber].type);
            return -1;
            break;
    }

    /*
     * Execute the modbus command
     */
    int ret = 0;
    int reg = regNumber;
    uint16_t value[4];
    memset(value,0,sizeof(value));
    switch(modbus->map[regNumber].command) {
        case MODBUS_CMD_3:
            reg -= modbus->cmd3Offset;
            ret = modbus_read_registers(ctx,reg,regLen,value);
            break;
        case MODBUS_CMD_4:
            reg -= modbus->cmd4Offset;
            ret = modbus_read_input_registers(ctx,reg,regLen,value);
            break;
        default:
            syslog(LOG_ERR, "Unknown command type: %d\n", modbus->map[regNumber].command);
            return -1;
            break;
    }

    if (ret < 0) {
        syslog(LOG_ERR, "Problem executing modbus read %d command: %d (%s)\n",modbus->map[regNumber].command,
                ret,modbus_strerror(errno));
        return -1;
    }

    /*
     * Transfer the response to the structure
     */
    modbus->map[regNumber].assignValue(value);

    return 0;
}

int Capture::save(SlaveMap *map, int slaveNumber) {
    /*
     * Setup the file counter index
     */
    ModbusInfo* modbus = NULL;
    for (const auto& slave : map->slaves) {
        modbus = (ModbusInfo*)slave.capture;
        if ((modbus != NULL) && (modbus->address == slaveNumber)) {
            /* Found. End the loop */
            break;
        }
        else {
            modbus = NULL;
        }
    }
    if (modbus == NULL) {
        syslog(LOG_ERR,"Capture: Slave not found in list: %d\n", slaveNumber);
        return -1;
    }
    modbus->filePos = (modbus->filePos == 9999) ? 0 : modbus->filePos + 1;
    /*
     * Build JSON structure
     */
    cJSON *root = buildJson(map,slaveNumber);
    if (root == NULL) {
        syslog(LOG_ERR, "Problem building slave %d register payload\n", slaveNumber);
        return -1;
    }
    /*
     * Generate output structure
     */
    char *output = cJSON_PrintUnformatted(root);
    if (output == NULL) {
        syslog(LOG_ERR, "Problem building slave %d output payload\n", slaveNumber);
        cJSON_Delete(root);
        return -1;
    }
    int outputLen = strlen(output);

    /*
     * Creating the filename
     */
    char filepath[256];
    memset(filepath,0,sizeof(filepath));
    sprintf(filepath,"%s/%03dT%04d.dat", 
            FILEPATH, slaveNumber, modbus->filePos);
    syslog(LOG_DEBUG, "Saving file %s\n",filepath);
    
    FILE *fp = NULL;
    fp = fopen(filepath,"w");
    if (fp == NULL) {
        syslog(LOG_ERR,"Problem open file for writing:%s:%d:%s\n",filepath,errno,strerror(errno));
        cJSON_Delete(root);
        free(output);
        return -1;
    }
    int nbWritten = fwrite(output,1,outputLen,fp);
    if (nbWritten < 0) {
        syslog(LOG_ERR, "Error writing register file: %s: %d: %s\n",filepath, errno, strerror(errno));
        if (errno == ENOSPC) {
            diskFull = true;
        }
    }
    else if (nbWritten != outputLen) {
        syslog(LOG_WARNING, "Incomplete write register file %s: %d / %d\n",filepath,nbWritten,outputLen);
    }

    syslog(LOG_INFO, "File %s saved\n",filepath);

    fclose(fp);
    cJSON_Delete(root);
    free(output);
    return (nbWritten < 0) ? -1 : 0;
}

cJSON* Capture::buildJson(SlaveMap *map, int slaveNumber) {
    /*
     * Search for the requested slave
     */
    ModbusInfo* modbus = NULL;
    for (const auto& slave : map->slaves) {
        modbus = (ModbusInfo*)slave.capture;
        if ((modbus != NULL) && (modbus->address == slaveNumber)) {
            /* Found. End the loop */
            break;
        }
        else {
            modbus = NULL;
        }
    }
    if (modbus == NULL) {
        syslog(LOG_ERR,"Capture: Slave not found in list: %d\n", slaveNumber);
        return NULL;
    }
    cJSON *root = cJSON_CreateObject();
    /*
     * Capture timestamp and add to json
     */
    time_t t;
    struct tm *now;
    time(&t);
    now = localtime(&t);
    char timestamp[24] = { 0 };
    memset(timestamp,0,sizeof(timestamp));
    sprintf(timestamp,"%04d-%02d-%02d %02d:%02d:%02d",
                (now->tm_year+1900),now->tm_mon,now->tm_mday,
                now->tm_hour,now->tm_min,now->tm_sec);
    cJSON_AddStringToObject(root,INT_JSON_TIMESTAMP,timestamp);
    /*
     * As an internal structure, the keys must be simple
     * in order to reduce the internal file size
     */
    cJSON *regs = cJSON_AddArrayToObject(root,INT_JSON_REGISTERS);
    for (auto& [regNb, value] : modbus->map) {
        cJSON* reg = cJSON_CreateObject();
        cJSON_AddNumberToObject(reg,INT_JSON_REGISTER,regNb);
        double val = value.exportValue();
        cJSON_AddNumberToObject(reg,INT_JSON_VALUE,val);
        // syslog(LOG_DEBUG,"Setting json: slaveNb=%d,address=%d,name=%s,value=%f\n",slaveNumber,regNb,value.name.c_str(),val);
        cJSON_AddItemToArray(regs, reg);
    }

    return root;
}

void Capture::initSlave(void) {

    query = (uint8_t*)malloc(MODBUS_RTU_MAX_ADU_LENGTH);
    if (query == NULL) {
        syslog(LOG_ERR, "Capture: Error query malloc()");
        return;
    }
}

bool Capture::isValidRequest(SlaveMap *map, int reqSlave, int reqAddress, int reqCommand) {
    /*
     * Search for the requested slave
     */
    ModbusInfo* modbus = NULL;
    for (const auto& slave : map->slaves) {
        modbus = (ModbusInfo*)slave.capture;
        if ((modbus != NULL) && (modbus->address == reqSlave)) {
            /* Found. End the loop */
            break;
        }
        else {
            modbus = NULL;
        }
    }
    if (modbus == NULL) {
        syslog(LOG_ERR,"Capture: Slave not found in list: %d\n", reqSlave);
        return false;
    }

    if (modbus->map.find(reqAddress) == modbus->map.end()) {
        syslog(LOG_ERR, "Capture: Address %d not found in slave %d\n", reqAddress, reqSlave);
        return false;
    }

    int command = 0;
    switch (modbus->map[reqAddress].command) {
        case MODBUS_CMD_3:
            command = MODBUS_FC_READ_HOLDING_REGISTERS;
            break;
        case MODBUS_CMD_4:
            command = MODBUS_FC_READ_INPUT_REGISTERS;
            break;
        default:
            syslog(LOG_WARNING,"Capture: Slave %d: Unknown registered command for address %d: %d\n",reqSlave, reqAddress, modbus->map[reqAddress].command);
            break;
    }

    if (command == MODBUS_FC_READ_HOLDING_REGISTERS) {
        if ((reqCommand != MODBUS_FC_READ_HOLDING_REGISTERS) && (reqCommand != MODBUS_FC_WRITE_SINGLE_REGISTER) &&
                (reqCommand != MODBUS_FC_WRITE_MULTIPLE_REGISTERS)) {
            syslog(LOG_ERR, "Capture: Command %d not found in address %d from slave %d\n",reqCommand,reqAddress,reqSlave);
            return false;
        }
    }
    else if (command != reqCommand) {
        syslog(LOG_ERR, "Capture: Command %d not found in address %d from slave %d\n",reqCommand,reqAddress,reqSlave);
        return false;
    }

    return true;
}

int Capture::getNbRegisters(void) {
    /*
     * Open the root directory
     */
    DIR *pDir = opendir(FILEPATH);
    if (pDir == NULL) {
        syslog(LOG_ERR, "Status: Cannot open directory %s\n", FILEPATH);
        return 0;
    }
    /*
     * Scan files
     */
    int counter = 0;
    struct dirent *pDirent;
    while ((pDirent = readdir(pDir)) != NULL) {
        if (strstr(pDirent->d_name,".dat") != NULL) {
            counter++;
        }
    }
    /*
     * Close the directory
     */
    closedir(pDir);
    /*
     * Evaluate the internal flag
     */
    if (counter > MAX_NB_LOG_FILES) {
        diskFull = true;
    }
    else {
        diskFull = false;
    }

    return counter;
}
