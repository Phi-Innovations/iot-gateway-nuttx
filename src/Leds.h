#pragma once

#include <nuttx/leds/userled.h>

#define LEDS_DEVPATH "/dev/userleds"
#define LEDS_LEDSET 0x1f
class Leds {
private:
    int ledsFd = -1;
    userled_set_t supported;

    userled_set_t status(void);
public:
    typedef enum {
        MODBUS = 1,
        NETWORK,
        TRANSMISSION,
        ERROR
    } Indicators_e;

    Leds();
    ~Leds();

    void on(Indicators_e led);
    void off(Indicators_e led);
    void toggle(Indicators_e led);
};
