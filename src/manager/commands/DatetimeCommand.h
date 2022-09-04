#pragma once
#include "CommandIF.h"

#include "netutils/cJSON.h"

class DatetimeCommand : public CommandIF {
    cJSON* execute(const std::string& input, SystemData *data);
};