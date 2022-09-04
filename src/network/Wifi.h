#pragma once

#include "data/SystemData.h"
#include "data/Configuration.h"
#include "NetworkIF.h"
#include "Leds.h"
#include "defs.h"

#include <nuttx/net/usrsock.h>
#include <arpa/inet.h>

#define SOCKET_BASE  10000
#define SOCKET_COUNT 16

class Wifi : public NetworkIF {
private:

    int usrsock = 0;
    int espsock = 0;
    bool hasUsrSock = false;
    bool hasEsp8266 = false;

    int usrsockRequest(void);
    ssize_t read_req(int fd, const struct usrsock_request_common_s *com_hdr,
         void *req, size_t reqsize);
    /*
     * Callbacks for usrsock requests
     */
    static int socket_request(int fd, void *hdrbuf);
    static int close_request(int fd, void *hdrbuf);
    static int connect_request(int fd, void *hdrbuf);
    static int sendto_request(int fd, void *hdrbuf);
    static int recvfrom_request(int fd, void *hdrbuf);
    static int setsockopt_request(int fd, void *hdrbuf);
    static int getsockopt_request(int fd, void *hdrbuf);
    static int getsockname_request(int fd, void *hdrbuf);
    static int getpeername_request(int fd, void *hdrbuf);
    static int bind_request(int fd, void *hdrbuf);
    static int listen_request(int fd, void *hdrbuf);
    static int accept_request(int fd, void *hdrbuf);
    static int ioctl_request(int fd, void *hdrbuf);
    /*
     * Socket handler structure
     */
    struct usrsock_req_handler_s {
        uint32_t hdrlen;
        int (*fn)(int fd, void *req);
    };
    struct usrsock_req_handler_s handlers[USRSOCK_REQUEST__MAX]  = {
        {
            sizeof(struct usrsock_request_socket_s),
            socket_request
        },
        {
            sizeof(struct usrsock_request_close_s),
            close_request
        },
        {
            sizeof(struct usrsock_request_connect_s),
            connect_request
        },
        {
            sizeof(struct usrsock_request_sendto_s),
            sendto_request
        },
        {
            sizeof(struct usrsock_request_recvfrom_s),
            recvfrom_request
        },
        {
            sizeof(struct usrsock_request_setsockopt_s),
            setsockopt_request
        },
        {
            sizeof(struct usrsock_request_getsockopt_s),
            getsockopt_request
        },
        {
            sizeof(struct usrsock_request_getsockname_s),
            getsockname_request
        },
        {
            sizeof(struct usrsock_request_getpeername_s),
            getpeername_request
        },
        {
            sizeof(struct usrsock_request_bind_s),
            bind_request
        },
        {
            sizeof(struct usrsock_request_listen_s),
            listen_request
        },
        {
            sizeof(struct usrsock_request_accept_s),
            accept_request
        },
        {
            sizeof(struct usrsock_request_ioctl_s),
            ioctl_request
        }
    };

    /*
     * Socket configuration
     */
    enum sock_state_e {
        CLOSED,
        OPENED,
        BOUND,
        CONNECTED,
    };
    struct usock_s {
        int8_t   type;
        char     cid;
        enum sock_state_e state;
        uint16_t lport;           /* local port */
        struct sockaddr_in raddr; /* remote addr */
    };
    struct usock_s sockets[SOCKET_COUNT];
    static int16_t socket_alloc(int type);
    static struct usock_s *socket_get(int sockid);
    static int socket_free(int sockid);

    static int _send_ack_common(int fd, uint8_t xid, struct usrsock_message_req_ack_s *resp);
    static int _write_to_usock(int fd, void *buf, size_t count);
    static int usock_send_event(int fd, struct usock_s *usock, int events);
public:
    Wifi(SystemData *data, Leds *leds);
    ~Wifi() { };

    void verify(SystemData *data);
};
