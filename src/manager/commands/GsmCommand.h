#pragma once
#include "CommandIF.h"

#include "netutils/cJSON.h"

class GsmCommand : public CommandIF {
    cJSON* execute(const cJSON *input, SystemData *data);
};