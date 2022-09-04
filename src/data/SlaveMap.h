#pragma once

#include "SlaveInfo.h"
#include <vector>

#include <netutils/cJSON.h>

class SlaveMap {
private:
    int load(void);
    void extractTransmission(int protocol, const cJSON* jsonTransmission, SlaveInfo& slave);
    void extractTransmissionMqtt(const cJSON* jsonTransmission, SlaveInfo& slave);
    void extractCapture(int protocol, const cJSON* jsonCapture, SlaveInfo& slave);
    void extractCaptureModbus(const cJSON* jsonCapture, SlaveInfo& slave);
    
public:
    std::vector<SlaveInfo> slaves;

    SlaveMap();
    ~SlaveMap();

    int save(void);
    int create(void);
    int process(const cJSON *config);
    cJSON* build(void);
};
