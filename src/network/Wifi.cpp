#include "Wifi.h"
#include "data/Configuration.h"

#include <syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <netutils/esp8266.h>
#include <poll.h>

Wifi::Wifi(SystemData *data, Leds *leds) : NetworkIF(leds) {
    /*
     * Starting USRSOCK
     */
    usrsock = open("/dev/usrsock", O_RDWR);
    if (usrsock < 0) {
        return;
    }
    hasUsrSock = true;
    /*
     * Initializing ESP8266 library
     */
    if (lesp_initialize() < 0) {
        return;
    }
    hasEsp8266 = true;
    /*
     * local instance
     */
    theInstance = this;
}

void Wifi::verify(SystemData *data) {
    struct pollfd fds[2];
    int ret;

    memset(fds, 0, sizeof(fds));
    /* 
     * Check events from usrsock
     */
    fds[0].fd = usrsock;
    fds[0].events = POLLIN;
    // fds[1].fd = fd[1];
    // fds[1].events = POLLIN;

    ret = poll(fds, 1, -1);
    if (fds[0].revents & POLLIN) {
        ret = usrsockRequest();
    }

    close(usrsock);
}

int Wifi::usrsockRequest(void) {
    FAR struct usrsock_request_common_s *com_hdr;
    uint8_t hdrbuf[16];
    ssize_t rlen;
    
    com_hdr = (FAR struct usrsock_request_common_s *)hdrbuf;
    rlen = read(usrsock, com_hdr, sizeof(*com_hdr));
    if (rlen < 0) {
        return -errno;
    }
    if (rlen != sizeof(*com_hdr)) {
        return -EMSGSIZE;
    }

    if (com_hdr->reqid >= USRSOCK_REQUEST__MAX || !handlers[com_hdr->reqid].fn) {
        return -EIO;
    }

    rlen = read_req(usrsock, com_hdr, hdrbuf, handlers[com_hdr->reqid].hdrlen);
    if (rlen < 0) {
        return rlen;
    }

    return handlers[com_hdr->reqid].fn(usrsock, hdrbuf);
}

ssize_t Wifi::read_req(int fd, const struct usrsock_request_common_s *com_hdr,
         void *req, size_t reqsize) {
    ssize_t rlen;

    rlen = read(fd, (uint8_t *)req + sizeof(*com_hdr),
                reqsize - sizeof(*com_hdr));
    if (rlen < 0) {
        return -errno;
    }

    if (rlen + sizeof(*com_hdr) != reqsize) {
        return -EMSGSIZE;
    }

    return rlen;
}

int Wifi::socket_request(int fd, void *hdrbuf) {
    struct usrsock_request_socket_s *req = (struct usrsock_request_socket_s *)hdrbuf;
    struct usrsock_message_req_ack_s resp;
    int16_t usockid;
    int ret;
    Wifi *wifi = (Wifi*)theInstance;

    syslog(LOG_DEBUG,"%s: start type=%d \n",__func__, req->type);

    /* 
     * Check domain requested
     */
    if (req->domain != AF_INET) {
        usockid = -EAFNOSUPPORT;
    }
    else {
        /*
         * Execute the socket request from ESP8266 library
         */
        wifi->espsock = lesp_socket(req->domain,req->type,req->protocol);
        if (wifi->espsock < 0) {
            syslog(LOG_ERR,"Wifi: problem creating esp8266 socket: %d (%s)\n",errno,strerror(errno));
            usockid = wifi->espsock;
        }
        else {
            /* 
             * Allocate socket. 
             */
            usockid = socket_alloc(req->type);
        }
    }
    /* 
     * Send ACK response
     */
    memset(&resp, 0, sizeof(resp));
    resp.result = usockid;
    ret = _send_ack_common(fd, req->head.xid, &resp);
    if (ret < 0) {
        return ret;
    }

    syslog(LOG_DEBUG,"%s: end \n", __func__);
    return 0;
}

int Wifi::close_request(int fd, void *hdrbuf) {
    struct usrsock_request_close_s *req = (struct usrsock_request_close_s *)hdrbuf;
    struct usrsock_message_req_ack_s resp;
    FAR struct usock_s *usock;
    char cid;
    int ret = 0;
    Wifi *wifi = (Wifi*)theInstance;

    syslog(LOG_DEBUG,"%s: start \n", __func__);

    /* 
     * Check if this socket exists. 
     */
    usock = socket_get(req->usockid);
    cid = usock->cid;
    if ((BOUND != usock->state) && (CONNECTED != usock->state)) {
        ret = -EBADFD;
    }
    else {
        /*
         * Close socket in ESP8266
         */
        lesp_closesocket(wifi->espsock);
    }
    /* 
     * Send ACK response 
     */
    memset(&resp, 0, sizeof(resp));
    resp.result = ret;
    ret = _send_ack_common(fd, req->head.xid, &resp);
    if (0 > ret) {
        return ret;
    }
    /* 
     * Free socket 
     */
    ret = socket_free(req->usockid);

    syslog(LOG_DEBUG,"%s: end \n", __func__);

    return 0;
}

int Wifi::connect_request(int fd, void *hdrbuf) {
    FAR struct usrsock_request_connect_s *req = (struct usrsock_request_connect_s *)hdrbuf;
    struct usrsock_message_req_ack_s resp;
    struct sockaddr_in addr;
    FAR struct usock_s *usock;
    int events;
    ssize_t wlen;
    ssize_t rlen;
    int ret = 0;
    Wifi *wifi = (Wifi*)theInstance;

    syslog(LOG_DEBUG,"%s: start \n", __func__);

    /* 
     * Check if this socket exists. 
     */
    usock = socket_get(req->usockid);
    if (!usock) {
        ret = -EBADFD;
    }
    if (ret == 0) {
        /* 
        * Check if this socket is already connected. 
        */
        if (CONNECTED == usock->state) {
            ret = -EISCONN;
        }
    }
    
    if (ret == 0) {
        /* 
        * Check if this socket is already connected. 
        */

        if (BOUND == usock->state) {
            if (usock->type == SOCK_STREAM) {
                ret = -EISCONN;
            }
            else {
                /* 
                 * Firstly, close the socket 
                 */
                lesp_closesocket(wifi->espsock);
                usock->state = OPENED;
            }
        }
    }

    if (ret == 0) {
        /* 
        * Check if address size ok. 
        */
        if (req->addrlen > sizeof(addr)) {
            ret = -EFAULT;
        }
    }

    if (ret == 0) {
        /* 
        * Read address. 
        */
        rlen = read(fd, &addr, sizeof(addr));
        if (rlen < 0 || rlen < req->addrlen) {
            ret = -EFAULT;
        }
    }

    if (ret == 0) {
        /* 
         * Check address family. 
         */
        if (addr.sin_family != AF_INET) {
            ret = -EAFNOSUPPORT;
        }
    }

    if (ret == 0) {
        /*
         * Execute the ESP8266 connection
         */
        ret = lesp_connect(wifi->espsock,(const struct sockaddr *)&addr, (socklen_t)sizeof(addr));
    }
    if (ret == 0) {
        usock->cid = 'z';
        usock->state = CONNECTED;
        usock->raddr = addr;
    }
    else {
        ret = -errno;
    }

    /* 
     * Send ACK response. 
     */
    memset(&resp, 0, sizeof(resp));
    resp.result = ret;
    ret = _send_ack_common(fd, req->head.xid, &resp);
    if (ret < 0) {
        return ret;
    }

    events = USRSOCK_EVENT_SENDTO_READY;
    wlen = usock_send_event(fd, usock, events);

    if (wlen < 0) {
        return wlen;
    }

    syslog(LOG_DEBUG, "%s: end \n", __func__);
    return 0;
}

int Wifi::sendto_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::recvfrom_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::setsockopt_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::getsockopt_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::getsockname_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::getpeername_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::bind_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::listen_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::accept_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::ioctl_request(int fd, void *hdrbuf) {
    return -ENOSYS;
}

int Wifi::_send_ack_common(int fd, uint8_t xid, FAR struct usrsock_message_req_ack_s *resp) {
    resp->head.msgid = USRSOCK_MESSAGE_RESPONSE_ACK;
    resp->head.flags = 0;
    resp->xid = xid;

    /* 
     * Send ACK response. 
     */
    return _write_to_usock(fd, resp, sizeof(*resp));
}

int Wifi::_write_to_usock(int fd, void *buf, size_t count) {
    ssize_t wlen;

    wlen = write(fd, buf, count);
    if (wlen < 0) {
        return -errno;
    }

    if (wlen != count) {
        return -ENOSPC;
    }

    return 0;
}

int Wifi::usock_send_event(int fd, struct Wifi::usock_s *usock, int events) {
    struct usrsock_message_socket_event_s event;
    int i;
    Wifi *wifi = (Wifi*)theInstance;

    memset(&event, 0, sizeof(event));
    event.head.flags = USRSOCK_MESSAGE_FLAG_EVENT;
    event.head.msgid = USRSOCK_MESSAGE_SOCKET_EVENT;

    for (i = 0; i < SOCKET_COUNT; i++) {
        if (usock == &wifi->sockets[i]) {
            break;
        }
    }

    if (i == SOCKET_COUNT) {
        return -EINVAL;
    }

    event.usockid = i + SOCKET_BASE;
    event.events = events;

    return _write_to_usock(fd, &event, sizeof(event));
}

int16_t Wifi::socket_alloc(int type) {
    FAR struct usock_s *usock;
    int16_t i;
    Wifi *wifi = (Wifi*)theInstance;

    for (i = 0; i < SOCKET_COUNT; i++) {
        usock = &wifi->sockets[i];

        if (CLOSED == usock->state) {
            memset(usock, 0, sizeof(*usock));
            usock->cid = 'z'; /* Invalidate cid */
            usock->state = OPENED;
            usock->type = type;
            return i + SOCKET_BASE;
        }
    }

    return -1;
}

struct Wifi::usock_s *Wifi::socket_get(int sockid) {
    Wifi *wifi = (Wifi*)theInstance;

    if (sockid < SOCKET_BASE) {
        return NULL;
    }
    sockid -= SOCKET_BASE;
    if (sockid >= SOCKET_COUNT) {
        return NULL;
    }

    return &wifi->sockets[sockid];
}

int Wifi::socket_free(int sockid) {
    struct usock_s *usock = socket_get(sockid);

    if (!usock) {
        return -EBADFD;
    }

    if (CLOSED == usock->state) {
        return -EFAULT;
    }

    usock->state = CLOSED;
    usock->cid = 'z'; /* invalid */

    return 0;
}
