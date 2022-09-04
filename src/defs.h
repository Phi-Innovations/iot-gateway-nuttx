#pragma once

#define MODE_CONFIGS_KRON       0
#define MODE_CONFIGS_KARCHER    0
#define MODE_CONFIGS_PHI        1

#define FILEPATH "/mnt/disk"
#define NAME_MAX 255

#define FW_UPDATE_BLOCK_LEN 256

#define FILES_PATH          "/mnt/disk"
#define CERT_FILENAME       "cert.pem"
#define CFG_FILENAME        "config.json"
#define MODBUS_FILENAME     "modbus.json"
#define FW_FILENAME         "phi-gw.bin"
#define CERTIFICATE_FILE    FILES_PATH "/" CERT_FILENAME
#define CONFIG_FILE         FILES_PATH "/" CFG_FILENAME
#define MODBUS_MAP          FILES_PATH "/" MODBUS_FILENAME
#define FIRMWARE_FILE       FILES_PATH "/" FW_FILENAME

#define INT_JSON_REGISTERS  "G"
#define INT_JSON_REGISTER   "R"
#define INT_JSON_TYPE       "T"
#define INT_JSON_VALUE      "V"
#define INT_JSON_TIMESTAMP  "TS"

#define NETWORK_ETHERNET_IFACE  "eth0"

#define MQTT_TX_BUFFER_LEN      4096
#define MQTT_RX_BUFFER_LEN      4096

#define UT_REGISTERS_ADDRESS        0
#define UT_REGISTERS_NB_MAX         100
#define UT_INPUT_REGISTERS_ADDRESS  0
#define UT_INPUT_REGISTERS_NB       100

#define MAX_NB_LOG_FILES            250

typedef enum {
    GW_FUNCTION_MODBUS_GATEWAY,
    GW_FUNCTION_MODBUS_DATALOGGER
} OperationModes_e;

typedef enum {
    PAYLOAD_TYPE_STD,
    PAYLOAD_TYPE_KRON
} PayloadTypes_e;

typedef enum {
    CONNECTION_TYPE_ETHERNET,
    CONNECTION_TYPE_WIFI,
    CONNECTION_TYPE_GSM
} ConnectionTypes_e;

typedef enum {
    PULSE_COUNTER_START_RISING
} PulseStartTypes_e;

typedef enum {
    MODBUS_TYPE_UINT16,
    MODBUS_TYPE_UINT32,
    MODBUS_TYPE_FLOAT,
    MODBUS_TYPE_FLOAT_ABCD,
    MODBUS_TYPE_FLOAT_DCBA,
    MODBUS_TYPE_FLOAT_BADC,
    MODBUS_TYPE_FLOAT_CDAB,
    MODBUS_TYPE_DOUBLE,
    MODBUS_TYPE_UNKNOWN
} RegisterType_e;

typedef enum {
    MODBUS_CMD_3,
    MODBUS_CMD_4
} CommandType_e;

typedef enum {
    TRANSMISSION_MODE_CONNECTED,
    TRANSMISSION_MODE_INDIVIDUAL,
    TRANSMISSION_MODE_STANDARD
} TransmissionMode_e;

typedef enum {
    TRANSMISSION_PROTOCOL_INVALID,
    TRANSMISSION_PROTOCOL_MQTT,
    TRANSMISSION_PROTOCOL_HTTP
} TransmissionPrototol_e;

typedef enum {
    CAPTURE_PROTOCOL_INVALID,
    CAPTURE_PROTOCOL_MODBUS_RTU,
    CAPTURE_PROTOCOL_MODBUS_TCP
} CapturePrototol_e;

typedef enum {
    STATUS_NETWORK_DISCONNECTED,
    STATUS_NETWOKK_CONNECTING,
    STATUS_NETWORK_CONNECTED
} StatusNetwork_e;

typedef enum {
    STATUS_GENERAL_ACTIVE,
    STATUS_GENERAL_ERROR,
    STATUS_CRITICAL_ERROR
} StatusGeneral_e;
