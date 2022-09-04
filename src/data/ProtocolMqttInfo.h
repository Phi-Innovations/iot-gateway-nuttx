#pragma once
#include "TransmissionInfo.h"
#include <string>

class  ProtocolMqttInfo : public TransmissionInfo
{
public:
    std::string hostAddress;
    std::string port;
    std::string username;
    std::string password;
    int payloadType;
};
