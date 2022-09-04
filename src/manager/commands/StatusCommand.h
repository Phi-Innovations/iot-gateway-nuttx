#pragma once
#include "CommandIF.h"

class StatusCommand : public CommandIF {
private:
    cJSON* buildStatusResponse(Status *status, Configuration *cfg);
public:
    cJSON* execute(Status *status, SystemData *data);
};
