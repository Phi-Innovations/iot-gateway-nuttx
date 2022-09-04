#include "MqttClient.h"
#include "data/ProtocolMqttInfo.h"
#include "data/ModbusInfo.h"

#include <debug.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>

Manager* MqttClient::_manager = NULL;
MqttClient* MqttClient::theInstance = NULL;

MqttClient::MqttClient(Manager *manager) {
    /* Initialize the internal pointer */
    MqttClient::_manager = manager;
    theInstance = this;

    client = (struct mqtt_client *)malloc(sizeof(struct mqtt_client));
    if (client == NULL) {
        syslog(LOG_ERR, "MqttClient: problem initializing main structure\n");
    }
    else {
        syslog(LOG_DEBUG, "MqttClient: initialized\n");
    }
}

MqttClient* MqttClient::getInstance(void) {
    return theInstance;
}

Manager* MqttClient::getManager(void) {
    return _manager;
}

MqttClient::~MqttClient() {
    if (client) {
        free(client);
        client = NULL;
    }
}

void MqttClient::reconnectCb(struct mqtt_client* client, void **reconnect_state_vptr) {
    struct reconnect_state_t *reconnect_state = *((struct reconnect_state_t**) reconnect_state_vptr);
    reconnect(client,reconnect_state);
}

void MqttClient::reconnect(struct mqtt_client* client, struct reconnect_state_t *reconnect_state) {
    
    /* Set the internal flag to disconnected */
    reconnect_state->connected = false;

    /* Close the clients socket if this isn't the initial reconnect call */
    // if (client->error != MQTT_ERROR_INITIAL_RECONNECT) {
    //     close(client->socketfd);
    // }

    /* Perform error handling here. */
    if (client->error != MQTT_ERROR_INITIAL_RECONNECT) {
        syslog(LOG_WARNING, "MqttClient: reconnect_client: called while client was in error state \"%s\"\n", 
               mqtt_error_str(client->error)
        );
    }

    if (reconnect_state->useTls) {
        syslog(LOG_DEBUG, "MqttClient: Reconnecting using TLS\n");

        mqtt_pal_ssl_handle sslCtx = open_nb_socket(&reconnect_state->tlsCtx,reconnect_state->hostname, 
                reconnect_state->port,CERTIFICATE_FILE);
        if (sslCtx == NULL) {
            syslog(LOG_ERR, "MqttClient: Failed to open ssl context: %d\n", errno);
            return;
        }

        /* Reinitialize the client. */
        mqtt_reinit(client, sslCtx, -1, 
                reconnect_state->sendbuf, reconnect_state->sendbufsz,
                reconnect_state->recvbuf, reconnect_state->recvbufsz
        );
    }
    else {
        syslog(LOG_DEBUG, "MqttClient: Reconnecting without TLS\n");
        
        mqtt_pal_socket_handle sockfd = open_nb_socket(reconnect_state->hostname, reconnect_state->port);
        if (sockfd == -1) {
            syslog(LOG_ERR, "MqttClient: Failed to open socket: %d\n", errno);
            return;
        }

        /* Reinitialize the client. */
        mqtt_reinit(client, NULL, sockfd, 
                reconnect_state->sendbuf, reconnect_state->sendbufsz,
                reconnect_state->recvbuf, reconnect_state->recvbufsz
        );
    }
    
    /* Ensure we have a clean session */
    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    /* Send connection request to the broker. */
    if (mqtt_connect(client, reconnect_state->clientId, NULL, NULL, 0, 
                        reconnect_state->username, reconnect_state->password, 
                        connect_flags, 400) != MQTT_OK) {
        syslog(LOG_ERR, "MqttClient: Problem connecting to MQTT broker\n");
        return;
    }
    syslog(LOG_INFO, "MqttClient: Connected to the broker: %s:%s\n",
                reconnect_state->hostname, reconnect_state->port);
    /* Set the internal connected state */
    reconnect_state->connected = true;

    /* Subscribe to the topic. */
    mqtt_subscribe(client, reconnect_state->topic, 0);
    syslog(LOG_DEBUG, "Subscribing to topic: %s\n",reconnect_state->topic);
}

#if 0
void MqttClient::start(Configuration *cfg) {
    /*
     * Sanity check
     */
    if (!client) {
        return;
    }
    /*
     * Setup the reconnection structure
     */
    memset(port,0,sizeof(port));
    sprintf(port,"%5d",cfg->mqtt.server.port);

    reconnectState.hostname = cfg->mqtt.server.address.c_str();
    reconnectState.port = port;
    reconnectState.topic = cfg->mqtt.cmdTopic.c_str();
    reconnectState.clientId = cfg->mqtt.cliendId.c_str();
    reconnectState.username = cfg->mqtt.username.c_str();
    reconnectState.password = cfg->mqtt.password.c_str();
    reconnectState.sendbuf = sendbuf;
    reconnectState.sendbufsz = sizeof(sendbuf);
    reconnectState.recvbuf = recvbuf;
    reconnectState.recvbufsz = sizeof(recvbuf);
    reconnectState.connected = false;
    /*
     * Initialize the use of TLS
     */
    reconnectState.useTls = (bool)cfg->mqtt.useTls;

    mqtt_init_reconnect(client, reconnectCb, &reconnectState, newMessageCb, NULL);

    /*
     * Launch the connection
     */
    syslog(LOG_DEBUG, "Connecting to the general broker: %s:%s\n",reconnectState.hostname,
                    reconnectState.port);
    reconnect(client,&reconnectState);
    /*
     * Set the flag to start sync
     */
    started = true;
}
#endif

void MqttClient::start(Configuration *cfg) {
    /*
     * Sanity check
     */
    if (!client) {
        return;
    }

    /*
     * Set the flag to start sync
     */
    started = false;

    if (cfg->mqtt.useTls) {
        syslog(LOG_DEBUG, "MqttClient: Connecting using TLS\n");

        mqtt_pal_ssl_handle sslCtx = open_nb_socket(&tlsCtx, cfg->mqtt.server.address.c_str(), std::to_string(cfg->mqtt.server.port).c_str(), CERTIFICATE_FILE);
        if (sslCtx == NULL) {
            syslog(LOG_ERR, "MqttClient: Failed to open ssl context: %d\n", errno);
            return;
        }

        /* Reinitialize the client. */
        mqtt_init(client, sslCtx, -1, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), newMessageCb, NULL);
    }
    else {
        mqtt_pal_socket_handle sockfd = open_nb_socket(cfg->mqtt.server.address.c_str(), std::to_string(cfg->mqtt.server.port).c_str());
        if (sockfd == -1) {
            syslog(LOG_ERR, "MqttClient: Failed to open socket: %d\n", errno);
            return;
        }

        /* Reinitialize the client. */
        mqtt_init(client, NULL, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), newMessageCb, NULL);
    }
    
    /* Ensure we have a clean session */
    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    /* Send connection request to the broker. */
    if (mqtt_connect(client, cfg->mqtt.cliendId.c_str(), NULL, NULL, 0, 
                        cfg->mqtt.username.c_str(), cfg->mqtt.password.c_str(), 
                        connect_flags, 400) != MQTT_OK) {
        syslog(LOG_ERR, "MqttClient: Problem connecting to MQTT broker\n");
        return;
    }
    syslog(LOG_INFO, "MqttClient: Connected to the broker: %s:%s\n",
                cfg->mqtt.server.address.c_str(), std::to_string(cfg->mqtt.server.port).c_str());    

    /* Subscribe to the topic. */
    if (mqtt_subscribe(client, cfg->mqtt.cmdTopic.c_str(), 0) != MQTT_OK) {
        syslog(LOG_ERR, "MqttClient: Problem sending subscribe request to topic %s\n",cfg->mqtt.cmdTopic.c_str());
    }
    else {
        syslog(LOG_INFO, "MqttClient: Subscribing to topic: %s\n",cfg->mqtt.cmdTopic.c_str());
    }    
    /*
     * Set the flag to start sync
     */
    started = true;
}

void MqttClient::connectToBroker(int slave, SlaveMap *map, Configuration *cfg) {
    /*
     * Sanity check
     */
    if (!client) {
        return;
    }

    /*
     * Set the flag to start sync
     */
    started = false;

    /*
     * Search for the correct connection info
     */
    ProtocolMqttInfo *connInfo = NULL;
    for (const auto& _slave : map->slaves) {
        ModbusInfo *modbus = (ModbusInfo*)_slave.capture;
        if (modbus->address == slave) {
            /*
             * Found the slave. Exiting the loop
             */
            connInfo = (ProtocolMqttInfo*)_slave.transmission;
            break;
        }
    }
    if (connInfo == NULL) {
        syslog(LOG_ERR,"MqttClient: slave not found");
        return;
    }

    if (cfg->mqtt.useTls) {
        syslog(LOG_DEBUG, "MqttClient: Connecting using TLS\n");

        mqtt_pal_ssl_handle sslCtx = open_nb_socket(&tlsCtx, connInfo->hostAddress.c_str(), connInfo->port.c_str(), CERTIFICATE_FILE);
        if (sslCtx == NULL) {
            syslog(LOG_ERR, "MqttClient: Failed to open ssl context: %d\n", errno);
            return;
        }

        /* Reinitialize the client. */
        mqtt_init(client, sslCtx, -1, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), newMessageCb, NULL);
    }
    else {
        mqtt_pal_socket_handle sockfd = open_nb_socket(connInfo->hostAddress.c_str(), connInfo->port.c_str());
        if (sockfd == -1) {
            syslog(LOG_ERR, "MqttClient: Failed to open socket: %d\n", errno);
            return;
        }

        /* Reinitialize the client. */
        mqtt_init(client, NULL, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), newMessageCb, NULL);
    }
    
    /* Ensure we have a clean session */
    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    /* Send connection request to the broker. */
    if (mqtt_connect(client, cfg->mqtt.cliendId.c_str(), NULL, NULL, 0, 
                        connInfo->username.c_str(), connInfo->password.c_str(), 
                        connect_flags, 400) != MQTT_OK) {
        syslog(LOG_ERR, "MqttClient: Problem connecting to MQTT broker\n");
        return;
    }
    syslog(LOG_INFO, "MqttClient: Connected to the broker: %s:%s\n",
                connInfo->hostAddress.c_str(), connInfo->port.c_str());    

    /* Subscribe to the topic. */
    if (mqtt_subscribe(client, cfg->mqtt.cmdTopic.c_str(), 0) != MQTT_OK) {
        syslog(LOG_ERR, "MqttClient: Problem sending subscribe request to topic %s\n",cfg->mqtt.cmdTopic.c_str());
    }
    else {
        syslog(LOG_INFO, "MqttClient: Subscribing to topic: %s\n",cfg->mqtt.cmdTopic.c_str());
    }    
    /*
     * Set the flag to start sync
     */
    started = true;
}

void MqttClient::stop(void) {
    /*
     * Sanity check
     */
    if (!client) {
        return;
    }

    if (!started) {
        return;
    }

    mqtt_disconnect(client);
    /*
     * Closing the socket
     */
    if (client->useTls) {
        struct mbedtls_context *ctx = &tlsCtx;
        mbedtls_net_context *net_ctx = &ctx->net_ctx;
        mbedtls_net_close(net_ctx);
    }
    else {
        close(client->socketfd);
    }
    syslog(LOG_DEBUG, "MqttClient: Disconnected from broker\n");
    /*
     * Update internal flag
     */
    reconnectState.connected = false;
    started = false;
}

int MqttClient::publish(std::string topic, std::string msg) {
    /*
     * Sanity check
     */
    if (!client) {
        return -1;
    }

    if (!started) {
        return -1;
    }

    int ret = mqtt_publish(client, topic.c_str(), msg.c_str(), msg.length(), MQTT_PUBLISH_QOS_0);
    if (ret != MQTT_OK) {
        syslog(LOG_ERR, "MqttClient: problem publishing message: %d\n", ret);
    }
    // else {
    //     syslog(LOG_INFO, "MqttClient: message published successfully\n");
    // }

    return (ret == MQTT_OK) ? 0 : -1;
}

int MqttClient::publish(std::string topic, char *msg, size_t len) {
    /*
     * Sanity check
     */
    if (!client) {
        return -1;
    }

    if (!started) {
        return -1;
    }

    int ret = mqtt_publish(client, topic.c_str(), msg, len, MQTT_PUBLISH_QOS_0);
    if (ret != MQTT_OK) {
        syslog(LOG_ERR, "MqttClient: problem publishing message: %d\n", ret);
    }
    else {
        syslog(LOG_INFO, "MqttClient: message published successfully\n");
    }

    return (ret == MQTT_OK) ? 0 : -1;
}

void MqttClient::sync(void) {
    /*
     * Sanity check
     */
    if (!client) {
        return;
    }
    /*
     * Only sync after at least one connect or start is launched
     */
    if (started) {
        mqtt_sync(client);
    }
}

void MqttClient::newMessageCb(void** message_state_vptr, struct mqtt_response_publish *published) {
    
    Manager *manager = getManager();
    if (manager == NULL) {
        syslog(LOG_ERR,"MqttClient: Manager component invalid\n");
        return;
    }
    /*
     * Check if it is a valid topic. In positive case, process the message
     */
    const std::string topic((char*)published->topic_name,published->topic_name_size);
    if (manager->isValidTopic(topic) == true) {
        syslog(LOG_DEBUG,"MqttClient: Enqueuing MQTT message\n");
        const std::string payload((char*)published->application_message,published->application_message_size);
        /*
         * Enqueue the payload
         */
        manager->addMqttCommand(payload);
    }

    syslog(LOG_DEBUG,"MqttClient: End of procedure\n");
}

bool MqttClient::isConnected(void) {
    // return reconnectState.connected;
    return started;
}

/*
    A template for opening a non-blocking POSIX socket.
*/
int MqttClient::open_nb_socket(const char* addr, const char* _port) {
    struct addrinfo hints = {0};

    hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Must be TCP */
    int sockfd = -1;
    int rv;
    struct addrinfo *p, *servinfo;

    /* get address information */
    rv = getaddrinfo(addr, _port, &hints, &servinfo);
    if(rv != 0) {
        syslog(LOG_ERR, "Failed to open socket (getaddrinfo): %s\n", gai_strerror(rv));
        return -1;
    }

    /* open the first possible socket */
    for(p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            syslog(LOG_ERR, "MqttClient: error socket() %d (%s)\n",errno,strerror(errno));
            continue;
        }
        /* connect to server */
        rv = connect(sockfd, p->ai_addr, p->ai_addrlen);
        if(rv == -1) {
            syslog(LOG_ERR, "MqttClient: error connect() %d (%s)\n",errno,strerror(errno));
            close(sockfd);
            sockfd = -1;
            continue;
        }
        break;
    }  

    /* free servinfo */
    freeaddrinfo(servinfo);

    /* make non-blocking */
#if !defined(WIN32)
    if (sockfd != -1) {
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK);
    }
#else
    if (sockfd != INVALID_SOCKET) {
        int iMode = 1;
        ioctlsocket(sockfd, FIONBIO, &iMode);
    }
#endif
#if defined(__VMS)
    /* 
        OpenVMS only partially implements fcntl. It works on file descriptors
        but silently fails on socket descriptors. So we need to fall back on
        to the older ioctl system to set non-blocking IO
    */
    int on = 1;                 
    if (sockfd != -1) ioctl(sockfd, FIONBIO, &on);
#endif

    /* return the new socket fd */
    return sockfd;
}

mqtt_pal_ssl_handle MqttClient::open_nb_socket(struct mbedtls_context *ctx, const char *hostname, const char *port, const char *ca_file) {
    const unsigned char *additional = (const unsigned char *)"PHI-GATEWAY";
    size_t additional_len = 6;
    int rv;

    mbedtls_net_context *net_ctx = &ctx->net_ctx;
    mbedtls_ssl_context *ssl_ctx = &ctx->ssl_ctx;
    mbedtls_ssl_config *ssl_conf = &ctx->ssl_conf;
    mbedtls_x509_crt *ca_crt = &ctx->ca_crt;
    mbedtls_entropy_context *entropy = &ctx->entropy;
    mbedtls_ctr_drbg_context *ctr_drbg = &ctx->ctr_drbg;

    /*
     * Change to 0 when done
     */
    mbedtls_debug_set_threshold(0);

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    rv = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                               additional, additional_len);
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_ctr_drbg_seed: %d\n",rv);
        return NULL;
    }

    mbedtls_x509_crt_init(ca_crt);
    rv = mbedtls_x509_crt_parse_file(ca_crt, ca_file);
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_x509_crt_parse_file: %d\n",rv);
        return NULL;
    }

    mbedtls_ssl_config_init(ssl_conf);
    rv = mbedtls_ssl_config_defaults(ssl_conf,  MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_ssl_config_defaults: %d\n",rv);
        return NULL;
    }
    mbedtls_ssl_conf_ca_chain(ssl_conf, ca_crt, NULL);
    mbedtls_ssl_conf_authmode(ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(ssl_conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(ssl_conf, mbedtls_my_debug, NULL );

    mbedtls_net_init(net_ctx);
    rv = mbedtls_net_connect(net_ctx, hostname, port, MBEDTLS_NET_PROTO_TCP);
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_net_connect: %d\n",rv);
        return NULL;
    }
    rv = mbedtls_net_set_nonblock(net_ctx);
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_net_set_nonblock: %d\n",rv);
        return NULL;
    }

    mbedtls_ssl_init(ssl_ctx);
    rv = mbedtls_ssl_setup(ssl_ctx, ssl_conf);
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_ssl_setup: %d\n",rv);
        return NULL;
    }
    rv = mbedtls_ssl_set_hostname(ssl_ctx, hostname);
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_ssl_set_hostname: %d\n",rv);
        return NULL;
    }
    mbedtls_ssl_set_bio(ssl_ctx, net_ctx,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    for (;;) {
        rv = mbedtls_ssl_handshake(ssl_ctx);
        uint32_t want = 0;
        if (rv == MBEDTLS_ERR_SSL_WANT_READ) {
            want |= MBEDTLS_NET_POLL_READ;
        } else if (rv == MBEDTLS_ERR_SSL_WANT_WRITE) {
            want |= MBEDTLS_NET_POLL_WRITE;
        } else {
            break;
        }
        rv = mbedtls_net_poll(net_ctx, want, -1);
        if (rv < 0) {
            syslog(LOG_ERR,"MqttClient: Error mbedtls_net_poll: %d\n",rv);
            return NULL;
        }
    }
    if (rv != 0) {
        syslog(LOG_ERR,"MqttClient: Error mbedtls_ssl_handshake: %d\n",rv);
        return NULL;
    }
    uint32_t result = mbedtls_ssl_get_verify_result(ssl_ctx);
    if (result != 0) {
        if (result == (uint32_t)-1) {
            syslog(LOG_ERR,"MqttClient: Error mbedtls_ssl_get_verify_result: %d\n",rv);
            return NULL;
        } else {
            char buf[512];
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "\t", rv);
            syslog(LOG_ERR, "Certificate verification failed (%0" PRIx32 ")\n%s\n", result, buf);
        }
    }

    /*
     * Return the socket
     */
    // return net_ctx->fd;
    return &ctx->ssl_ctx;
}

void MqttClient::mbedtls_my_debug( void *ctx, int level, const char *file, int line, const char *str ) {
	syslog(LOG_DEBUG, "%d:%s:%04d: %s", level, file, line, str );
}