#pragma once

#include "data/SystemData.h"
#include "data/Configuration.h"
#include "Leds.h"
#include "defs.h"

class NetworkIF {
protected:
    static NetworkIF* theInstance;

    Leds *_leds = NULL;
    bool plugged = false;
    bool hasIP = false;
    int  ifaceSocket = 0;
public:
    NetworkIF(Leds *leds);
    ~NetworkIF() { };

    virtual void verify(SystemData *data) { }
    StatusNetwork_e getState(void);

    static bool isPlugged(void);
};
