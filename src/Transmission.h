#pragma once

#include "data/SystemData.h"
#include "MqttClient.h"
#include "Leds.h"

#include <chrono>

class Transmission {
private:
    Leds *_leds = NULL;

    typedef enum {
        STATE_IDLE,
        STATE_CONNECTING,
        STATE_CONNECTED
    } TransmissionStates_e;
    TransmissionStates_e state = STATE_IDLE;
    bool transmissionStarted = false;

    std::chrono::time_point<std::chrono::system_clock> sendTimer;
    SystemData *_data;
    MqttClient *_mqttClient;
    
    std::vector<int> slaveList;
    std::vector<std::string> fileList;
    int currentSlave = 0;

    void runIdleState();
    void runConnectingState();
    void runConnectedState();

    void buildSend(int slave, std::string filepath);
    void buildFileList(int slave);
public:
    Transmission(SystemData *data, MqttClient *mqttClient, Leds *leds);
    ~Transmission() { }
    
    void run(void);
};
