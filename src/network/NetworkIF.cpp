#include "NetworkIF.h"
#include "data/Configuration.h"

NetworkIF* NetworkIF::theInstance = NULL;

NetworkIF::NetworkIF(Leds *leds) : _leds(leds) {

}

bool NetworkIF::isPlugged(void) {
    /*
     * The network will be considered plugged only when
     * there is a valid network interface and an assigned
     * IP address.
     */
    NetworkIF *net = NetworkIF::theInstance;

    if (net == NULL) {
        return false;
    }

    return (net->plugged && net->hasIP) ? true : false;
}

StatusNetwork_e NetworkIF::getState(void) {
    /*
     * For now, only evaluate the plugged flag
     */
    if (isPlugged()) {
        return STATUS_NETWORK_CONNECTED;
    }
    else {
        return STATUS_NETWORK_DISCONNECTED;
    }
}
