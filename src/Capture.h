#pragma once

#include "data/SystemData.h"
#include "data/Status.h"
#include "modbus.h"
#include "Leds.h"

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>
#include <netutils/cJSON.h>

#include <vector>
#include <chrono>

class Capture {
private:
    Leds *_leds = NULL;
    Status *_status = NULL;

    typedef enum {
        WAITING,
        SCANNING,
        ERROR
    } CaptureStates_e;

    modbus_t *ctx = NULL;
    std::vector<int> slaveList;
    std::vector<int> registerList;
    int currentSlave = 0;
    CaptureStates_e state;
    std::chrono::time_point<std::chrono::system_clock> scanTimer;
    bool diskFull = false;

    int readRegister(SlaveMap *map, int slaveNb, int regNumber);
    int save(SlaveMap *map, int slaveNumber);
    cJSON* buildJson(SlaveMap *map, int slavevNumber);
    void initializeFileIndex(SlaveMap *map);
    /*
     * Modbus slave components
     */
    // modbus_mapping_t *mb_mapping = NULL;
    uint8_t *query = NULL;
    int header_length;
    void initSlave(void);
    // bool loadMapValues(ModbusMap *map, int reqSlave, int reqAddress, int reqCommand);
    // bool updateMapValues(ModbusMap *map, int reqSlave, int reqAddress);
    bool isValidRequest(SlaveMap *map, int reqSlave, int reqAddress, int reqCommand);
public:
    Capture(SystemData *data, Leds *leds, Status *status);
    ~Capture();
    int scan(SystemData *data);
    int getNbRegisters(void);
    bool isDiskFull(void) { return diskFull; }
};