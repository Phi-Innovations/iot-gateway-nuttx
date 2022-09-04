#include "Leds.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <syslog.h>

Leds::Leds() {
    ledsFd = open(LEDS_DEVPATH, O_WRONLY);
    if (ledsFd < 0) {
        syslog(LOG_ERR, "Leds: Problem starting leds driver\n");
        return;
    }

    int ret = ioctl(ledsFd, ULEDIOC_SUPPORTED,
              (unsigned long)((uintptr_t)&supported));
    if (ret < 0) {
        int errcode = errno;
        syslog(LOG_ERR, "Leds: ioctl(ULEDIOC_SUPPORTED) failed: %d\n", errcode);
        close(ledsFd);
        ledsFd = -1;
        return;
    }

    /* 
     * Excluded any LEDs that not supported AND not in the set of LEDs the
     * user asked us to use.
     */

    syslog(LOG_INFO, "Leds: Supported LEDs 0x%02x\n", (unsigned int)supported);
    supported &= LEDS_LEDSET;

    userled_set_t ledset = 0x1E;
    if (ioctl(ledsFd, ULEDIOC_SETALL, ledset) < 0) {
        int errcode = errno;
        syslog(LOG_ERR, "Leds: (ULEDIOC_SETALL) Problem clearing all leds: %d\n", errcode);
    }
}

Leds::~Leds() {
    if (ledsFd < 0) {
        return;
    }

    close(ledsFd);
}

void Leds::on(Indicators_e led) {
    /*
     * Get the current state of the led, for not disturbing the
     * operation of the other leds
     */
    userled_set_t ledset = status();

    /* 
     * Clearing the bit, which will turn on the led 
     */
    ledset &= ~(1 << led);

    /*
     * Updating the map
     */
    if (ioctl(ledsFd, ULEDIOC_SETALL, ledset) < 0) {
        int errcode = errno;
        syslog(LOG_ERR, "Leds: (ULEDIOC_SETALL) Problem turning on led %d: %d\n", led, errcode);
    }
}

void Leds::off(Indicators_e led) {
    /*
     * Get the current state of the led, for not disturbing the
     * operation of the other leds
     */
    userled_set_t ledset = status();

    /* 
     * Setting the bit, which will turn off the led 
     */
    ledset |= (1 << led);

    /*
     * Updating the map
     */
    if (ioctl(ledsFd, ULEDIOC_SETALL, ledset) < 0) {
        int errcode = errno;
        syslog(LOG_ERR, "Leds: (ULEDIOC_SETALL) Problem turning off led %d: %d\n", led, errcode);
    }
}

void Leds::toggle(Indicators_e led) {
    /*
     * Get the current state of the led, for not disturbing the
     * operation of the other leds
     */
    userled_set_t ledset = status();

    /* 
     * Toggling the bit
     */
    ledset ^= (1 << led);

    /*
     * Updating the map
     */
    if (ioctl(ledsFd, ULEDIOC_SETALL, ledset) < 0) {
        int errcode = errno;
        syslog(LOG_ERR, "Leds: (ULEDIOC_SETALL) Problem turning off led %d: %d\n", led, errcode);
    }
}

userled_set_t Leds::status(void) {
    userled_set_t ledset = 0;
    /*
     * Get the current state of all leds
     */
    if (ioctl(ledsFd, ULEDIOC_GETALL, &ledset) < 0) {
        int errcode = errno;
        syslog(LOG_ERR, "Leds: (ULEDIOC_GETALL) Problem getting leds status: %d\n", errcode);
        return 0xFF;
    }

    return (uint8_t)(ledset & supported);
}
