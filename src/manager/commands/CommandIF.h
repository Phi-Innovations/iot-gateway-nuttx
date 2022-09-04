#pragma once
#include "data/SystemData.h"
#include "data/Status.h"

#include "netutils/cJSON.h"

#define STX '\x02'
#define ETX '\x03'

class CommandIF {
protected:
    static int sendResponse(int fd, const cJSON *output);
public:
    bool isStringPayload = false;
    
    virtual cJSON* execute(const cJSON* input, SystemData *data) { return NULL; }
    virtual cJSON* execute(const std::string& input, SystemData *data) { return NULL; }
    virtual cJSON* execute(Status *status, SystemData *data) { return NULL; }
};
