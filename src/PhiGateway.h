#pragma once
#include "data/SystemData.h"
#include "manager/Manager.h"
#include "Capture.h"
#include "network/NetworkIF.h"
#include "MqttClient.h"
#include "Transmission.h"
#include "Leds.h"
#include "data/Status.h"

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <pthread.h>
#include <string_view>

#include "cdcacm.h"

class PhiGateway {
private:
    SystemData      *data = NULL;
    Status          *status = NULL;
    MqttClient      *mqttClient = NULL;
    Manager         *manager = NULL;

    bool ready = false;

    Capture         *capture = NULL;
    NetworkIF       *network = NULL;
    Transmission    *transmission = NULL;
    Leds            *leds = NULL;

    void updateStatus(void);
    void processMqttCommands(void);

    void showBaseConfig(void);
public:
    PhiGateway(SystemData *_data, Status *_status, MqttClient *_mqtt, Manager *_manager);
    ~PhiGateway();

    int run(void);
};
