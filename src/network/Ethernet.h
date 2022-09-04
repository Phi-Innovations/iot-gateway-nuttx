#pragma once

#include "data/SystemData.h"
#include "data/Configuration.h"
#include "NetworkIF.h"
#include "Leds.h"
#include "defs.h"

class Ethernet : public NetworkIF {
private:

    void setupIP(Configuration *cfg);
    void setupInterface(Configuration *cfg);
    void verifyInterface(Configuration *cfg);

public:
    Ethernet(SystemData *data, Leds *leds);
    ~Ethernet() { };

    void verify(SystemData *data);
};
