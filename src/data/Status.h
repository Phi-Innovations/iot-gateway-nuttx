#pragma once

#include "defs.h"
#include "version.h"

#include <string>

struct Status {
    const char *version = FIRMWARE_VERSION;
    std::string ip;
    StatusNetwork_e networkState = STATUS_NETWORK_DISCONNECTED;
    int nbStoreRegisters = 0;
    StatusGeneral_e state = STATUS_GENERAL_ACTIVE;
    bool diskFull = false;
};
