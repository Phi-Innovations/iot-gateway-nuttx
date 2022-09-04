#pragma once

#include "data/Configuration.h"
#include "data/SlaveMap.h"
#include "defs.h"
#include "manager/Manager.h"

#include "mqtt.h"

#include <string>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/debug.h>

/**
 * @brief A structure that I will use to keep track of some data needed 
 *        to setup the connection to the broker.
 * 
 * An instance of this struct will be created in my \c main(). Then, whenever
 * \ref reconnect_client is called, this instance will be passed. 
 */

struct mbedtls_context {
    mbedtls_net_context net_ctx;
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_crt;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

struct reconnect_state_t {
    const char* hostname = NULL;
    const char* port = NULL;
    const char* topic = NULL;
    const char* clientId = NULL;
    const char* username = NULL;
    const char* password = NULL;
    uint8_t* sendbuf = NULL;
    size_t sendbufsz = 0;
    uint8_t* recvbuf = NULL;
    size_t recvbufsz = 0;
    bool connected = false;
    bool useTls = false;
    struct mbedtls_context tlsCtx;
};

class MqttClient {
private:
    bool started = false;
    char port[6];

    static Manager *_manager;
    static MqttClient *theInstance;
    
    struct mbedtls_context tlsCtx;
    struct mqtt_client *client = NULL;
    struct reconnect_state_t reconnectState;
    uint8_t sendbuf[MQTT_TX_BUFFER_LEN]; /* sendbuf should be large enough to hold multiple whole mqtt messages */
    uint8_t recvbuf[MQTT_RX_BUFFER_LEN]; /* recvbuf should be large enough any whole mqtt message expected to be received */

    static void reconnectCb(struct mqtt_client* client, void **reconnect_state_vptr);
    static void reconnect(struct mqtt_client* client, struct reconnect_state_t *reconnect_state);
    static void newMessageCb(void** message_state_vptr, struct mqtt_response_publish *published);

    static int open_nb_socket(const char* addr, const char* port);
    static mqtt_pal_ssl_handle open_nb_socket(struct mbedtls_context *ctx, const char *hostname, const char *port, const char *ca_file);
    static void mbedtls_my_debug( void *ctx, int level, const char *file, int line, const char *str );

    static MqttClient* getInstance(void);
    static Manager* getManager(void);

public:
    MqttClient(Manager *manager);
    ~MqttClient();

    int publish(std::string topic, std::string msg);
    int publish(std::string topic, char *msg, size_t len);
    void sync(void);
    void start(Configuration *cfg);
    void connectToBroker(int slave, SlaveMap *map, Configuration *cfg);
    void stop(void);
    bool isConnected(void);
};