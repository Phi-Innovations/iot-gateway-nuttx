#pragma once

#include <vector>
#include "data/SlaveInfo.h"

class ModbusUtils {
public:
    static std::vector<int> buildAddressList(const std::vector<SlaveInfo>& slaves);
    static std::vector<int> buildRegisterList(const std::vector<SlaveInfo>& slaves, int address);
    static bool hasSlaveAddress(const std::vector<SlaveInfo>& slaves, int address);
};