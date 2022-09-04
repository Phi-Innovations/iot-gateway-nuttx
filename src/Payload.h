#pragma once
#include "data/SlaveMap.h"

#include <netutils/cJSON.h>

class Payload {
public:
    static cJSON* buildStandard(int deviceId, int slaveNumber, char *data, SlaveMap* map);
    static cJSON* buildKron(int slaveNumber, char *data, SlaveMap* map);
};
