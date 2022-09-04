#pragma once

#include "TransmissionInfo.h"
#include "CaptureInfo.h"

#include <string>
#include <map>

class SlaveInfo {
public:
    TransmissionInfo    *transmission = NULL;
    CaptureInfo         *capture = NULL;
};
