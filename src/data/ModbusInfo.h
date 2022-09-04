#pragma once

#include <string>
#include <map>
#include "CaptureInfo.h"
#include "ModbusRegister.h"

class ModbusInfo : public CaptureInfo {
public:
    int filePos = 0; /* Internal use */
    int cmd4Offset;
    int cmd3Offset;
    int address;
    std::string serverAddress;
    int serverPort;
    std::map<int, ModbusRegister> map;
};
