#pragma once

#include <stdint.h>
#include <string>
#include "defs.h"

class ModbusRegister {
public:
    int command;
    int type;
    std::string name;
    uint16_t value[4];

    void exportValue(uint16_t *out);
    const double exportValue(void);
    void assignValue(uint16_t *in);
    void assignValue(double val);
};
