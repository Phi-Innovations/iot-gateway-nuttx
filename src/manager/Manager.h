#pragma once
#include "data/SystemData.h"
#include "data/Status.h"
#include "cdcacm.h"
#include "commands/CommandIF.h"
#include "commands/ConfigCommand.h"
#include "commands/MqttCommand.h"
#include "commands/EthernetCommand.h"
#include "commands/WifiCommand.h"
#include "commands/GsmCommand.h"
#include "commands/ModbusCommand.h"
#include "commands/DatetimeCommand.h"
#include "commands/DeviceIdCommand.h"
#include "commands/OperationCommand.h"
#include "commands/ScanGeneralCommand.h"
#include "commands/ScanMapCommand.h"
#include "commands/CertCommand.h"
#include "commands/SystemCommand.h"
#include "commands/UpdateCommand.h"
#include "commands/StatusCommand.h"
#include "commands/ModbusReadCommand.h"
#include "commands/ModbusWriteCommand.h"

#include <map>
#include <queue>

#include <netutils/cJSON.h>

class Manager {
private:
    struct cdcacm_state_s g_cdcacm;
    int startUSB(void);
    int stopUSB(void);
    int usbFD = 0;

    enum SourceType_e {
        SOURCE_USB,
        SOURCE_MQTT
    };
    
    enum UsbStates_e {
        STARTING,
        RUNNING
    };
    UsbStates_e state = STARTING;

    enum MsgStates_e {
        WAITING,
        RECEIVING
    };
    MsgStates_e msgState = WAITING;
    bool newMessage = false;

    char rxBuf[3072];
    char msgBuf[3072];
    int msgBufPos = 0;

    void processRxBuffer(int nbBytes);
    cJSON* evaluateMessage(void);
    cJSON* evaluateMessage(char *msg, size_t len);
    int sendResponse(int fd, const cJSON *output);

    bool updateMode = false;

    SystemData *data = NULL;
    Status *status = NULL;

    ConfigCommand       *configCmd = NULL;
    MqttCommand         *mqttCmd = NULL;
    EthernetCommand     *ethCmd = NULL;
    WifiCommand         *wifiCmd = NULL;
    GsmCommand          *gsmCmd = NULL;
    ModbusCommand       *modbusCmd = NULL;
    DatetimeCommand     *datetimeCmd = NULL;
    DeviceIdCommand     *deviceidCmd = NULL;
    OperationCommand    *operationCmd = NULL;
    ScanGeneralCommand  *scanCmd = NULL;
    ScanMapCommand      *scanMapCmd = NULL;
    CertCommand         *certCmd = NULL;
    SystemCommand       *systemCmd = NULL;
    UpdateCommand       *updateCmd = NULL;
    StatusCommand       *statusCmd = NULL;
    ModbusReadCommand   *modbusReadCmd = NULL;
    ModbusWriteCommand  *modbusWriteCmd = NULL;

    std::map<std::string,CommandIF*> map;
    std::queue<std::string> mqttCmdList;
public:
    Manager(SystemData *_data, Status *_status);
    ~Manager();
    void run(void);

    bool isUpdateMode(void) { return updateMode; }

    bool isValidTopic(const std::string& topic);
    std::string getRespTopic(void);
    void addMqttCommand(std::string cmd);
    std::string getMqttCommand(void);

    cJSON* evaluateMessage(std::string msg);
};
