#include "ModbusUtils.h"
#include "data/ModbusInfo.h"

std::vector<int> ModbusUtils::buildAddressList(const std::vector<SlaveInfo>& slaves) {
    std::vector<int> slaveList;

    for(const auto& slave : slaves) {
        const ModbusInfo* modbus = (ModbusInfo*)slave.capture;
        slaveList.push_back(modbus->address);
    }

    return slaveList;
}

std::vector<int> ModbusUtils::buildRegisterList(const std::vector<SlaveInfo>& slaves, int address) {
    std::vector<int> regList;

    for(const auto& slave : slaves) {
        const ModbusInfo* modbus = (ModbusInfo*)slave.capture;
        if (modbus->address == address) {
            /*
             * Found the address. Getting the registers
             */
            for(const auto& [key, value] : modbus->map) {
                regList.push_back(key);
            }
            /*
             * End the loop
             */
            break;
        }
    }

    return regList;
}

bool ModbusUtils::hasSlaveAddress(const std::vector<SlaveInfo>& slaves, int address) {
    for(const auto& slave : slaves) {
        const ModbusInfo* modbus = (ModbusInfo*)slave.capture;
        if (modbus->address == address) {
            /*
             * Found the address. Getting the registers
             */
            return true;
        }
    }

    return false;
}