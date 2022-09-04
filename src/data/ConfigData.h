#pragma once

#include "Configuration.h"

#include <string>

class ConfigData {
public:
    static std::string buildConfigFileContent(Configuration *cfg);
    static int extractConfigFileContent(const char *data, Configuration *cfg);
};
