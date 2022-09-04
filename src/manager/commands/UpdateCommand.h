#pragma once
#include "CommandIF.h"

#include "netutils/cJSON.h"

class UpdateCommand : public CommandIF {
private:
    void removeFiles(void);
public:
    bool updateMode = false;
    cJSON* execute(const cJSON *input, SystemData *data);
};