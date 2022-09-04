#pragma once
#include "CommandIF.h"

#include "netutils/cJSON.h"

class OperationCommand : public CommandIF {
    cJSON* execute(const cJSON *input, SystemData *data);
};