#pragma once

#include <string>

struct SimCardInfo {
    std::string apn;
    std::string user;
    std::string pwd;
    int connId;
    int direct_mode;
};
