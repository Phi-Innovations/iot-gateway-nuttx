#pragma once
#include "CommandIF.h"

#include "netutils/cJSON.h"

class ModbusReadCommand : public CommandIF {
    cJSON* execute(const cJSON *input, SystemData *data);
};