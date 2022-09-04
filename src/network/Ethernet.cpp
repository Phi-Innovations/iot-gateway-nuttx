#include "Ethernet.h"
#include "data/Configuration.h"

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nuttx/net/arp.h>
#include <nuttx/net/mii.h>
#include <nuttx/net/ioctl.h>
#include "netutils/netlib.h"
#include "netutils/dhcpc.h"
#include <syslog.h>
#include <string.h>
#include <sys/ioctl.h>

void Ethernet::setupInterface(Configuration *cfg) {
    uint8_t mac[IFHWADDRLEN];

    if (sscanf(cfg->net.macAddress.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
        syslog(LOG_ERR, "Network: problem extracting MAC address for ethernet configuration\n");
        return;
    }
    netlib_setmacaddr(NETWORK_ETHERNET_IFACE, mac);

    /*
     * Start socket used to detect the interface status
     */
    ifaceSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (ifaceSocket < 0) {
        syslog(LOG_ERR, "Failed to create a ethernet network interface socket: %d (%s)\n", errno, strerror(errno));
        ifaceSocket = -1;
    }

    /* 
     * Starting network interface and MAC address
     *
     * New versions of netlib_set_ipvXaddr will not bring the network up,
     * So ensure the network is really up at this point.
     */
    if (netlib_ifup(NETWORK_ETHERNET_IFACE) == 0) {
        plugged = true;
        // syslog(LOG_DEBUG, "Network: Ethernet initialized\n");
    }
    else {
        plugged = false;
    }
}

void Ethernet::setupIP(Configuration *cfg) {
    struct dhcpc_state ds;
    void *handle;
    struct in_addr addr;
    struct in_addr dns;
    uint8_t mac[IFHWADDRLEN];
    /* 
     * Get the MAC address of the NIC
     */
    netlib_getmacaddr(NETWORK_ETHERNET_IFACE, mac);
    /*
     * Assign the IP Address according to the configuration
     */
    if (cfg->net.isDHCP) {
        // syslog(LOG_DEBUG, "Setup network: DHCP\n");
        /* 
         * Set up the DHCPC modules
         */
        handle = dhcpc_open(NETWORK_ETHERNET_IFACE, &mac, IFHWADDRLEN);
        /* 
         * Get an IP address.  Note:  there is no logic here for renewing the address in this
         * example.  The address should be renewed in ds.lease_time/2 seconds.
         */
        if (!handle) {
            // syslog(LOG_ERR, "Problem dhcp_open()\n");
            hasIP = false;
        }
        else {
            if (dhcpc_request(handle, &ds) != OK) {
                // syslog(LOG_ERR, "Problem dhcp_request()\n");
                hasIP = false;
            }
            else {
                /*
                 * Set the flag indicating DHCP worked successfully
                 */
                hasIP = true;
            }
        }
        if (hasIP) {
            /*
             * Resetting the network configurationn based on the values
             * obtained from the DHCP response.
             */
            netlib_set_ipv4addr(NETWORK_ETHERNET_IFACE, &ds.ipaddr);
            if (ds.netmask.s_addr != 0) {
                netlib_set_ipv4netmask(NETWORK_ETHERNET_IFACE, &ds.netmask);
            }
            if (ds.default_router.s_addr != 0) {
                netlib_set_dripv4addr(NETWORK_ETHERNET_IFACE, &ds.default_router);
            }
            if (ds.dnsaddr.s_addr != 0) {
                dns.s_addr = ds.dnsaddr.s_addr;
                netlib_set_ipv4dnsaddr(&dns);
            }
        }
        dhcpc_close(handle);
    }
    else {
        /* 
         * Initializing base fixed network configuration
         */
        addr.s_addr = inet_addr(cfg->net.ipAddr.c_str());
        netlib_set_ipv4addr(NETWORK_ETHERNET_IFACE, &addr);
        addr.s_addr = HTONL(inet_addr(cfg->net.gateway.c_str()));
        netlib_set_dripv4addr(NETWORK_ETHERNET_IFACE, &addr);
        addr.s_addr = HTONL(inet_addr(cfg->net.netmask.c_str()));
        netlib_set_ipv4netmask(NETWORK_ETHERNET_IFACE, &addr);
        dns.s_addr = HTONL(inet_addr(cfg->net.dns.c_str()));
        netlib_set_ipv4dnsaddr(&dns);
        /*
         * Set the flag indicating IP address assigned
         */
        hasIP = true;
    }

    if (hasIP) {
        syslog(LOG_INFO, "Ethernet network configuration\n");
        netlib_get_ipv4addr(NETWORK_ETHERNET_IFACE,&addr);
        syslog(LOG_INFO, " IP Address: %s\n",inet_ntoa(addr));
        netlib_get_ipv4netmask(NETWORK_ETHERNET_IFACE,&addr);
        syslog(LOG_INFO, "Subnet mask: %s\n",inet_ntoa(addr));
        netlib_get_dripv4addr(NETWORK_ETHERNET_IFACE,&addr);
        syslog(LOG_INFO, "    Gateway: %s\n",inet_ntoa(addr));
        syslog(LOG_INFO, "        DNS: %s\n",inet_ntoa(dns));
        memset(mac,0,sizeof(mac));
        netlib_getmacaddr(NETWORK_ETHERNET_IFACE,mac);
        syslog(LOG_INFO, "        MAC: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
                mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    }
}

Ethernet::Ethernet(SystemData *data, Leds *leds) : NetworkIF(leds) {
    Configuration *cfg = data->cfg;

    theInstance = this;

    setupInterface(cfg);
    setupIP(cfg);
}

void Ethernet::verifyInterface(Configuration *cfg) {
    struct ifreq ifr;
    int ret = 0;
    uint8_t if_flags = 0;
    bool devup;

    /*
     * Get the current network interface situation
     */
    ret = netlib_getifstatus(NETWORK_ETHERNET_IFACE,&if_flags);
    if (ret < 0) {
        syslog(LOG_ERR, "Network: Problem reading network interface current status\n");
        plugged = false;
        return;
    }
    devup = IFF_IS_UP(if_flags);

    /*
     * Check the link state from the MAC
     */
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
    ifr.ifr_mii_reg_num = MII_MSR;

    ret = ioctl(ifaceSocket, SIOCGMIIREG, (unsigned long)&ifr);
    if (ret < 0) {
        syslog(LOG_ERR, "Network: ioctl(SIOCGMIIREG) failed: %d errno=%d (%s)\n", ret,errno,strerror(errno));
        plugged = false;
        return;
    }
    // syslog(LOG_DEBUG, "Network: %s: PHY address=%02x MSR=%04x\n",
    //     ifr.ifr_name, ifr.ifr_mii_phy_id, ifr.ifr_mii_val_out);

    /* 
     * Check for link up or down 
     */
    if ((ifr.ifr_mii_val_out & MII_MSR_LINKSTATUS) != 0) {
        /*
         * Link up
         */
        if (!devup) {
            /*
             * Bringing up the network interface
             */
            plugged = false;
            hasIP = false;
            syslog(LOG_DEBUG,"Network: LINK UP. Bringing up\n");
            if (netlib_ifup(NETWORK_ETHERNET_IFACE) == 0) {
                plugged = true;
                // syslog(LOG_DEBUG, "Network: Ethernet activated\n");
            }
        }
    }
    else {
        /*
         * Link Down
         */
        if (devup) {
            syslog(LOG_DEBUG,"Network: LINK DOWN. Shutting down\n");
            if (netlib_ifdown(NETWORK_ETHERNET_IFACE) == 0) {
                // syslog(LOG_DEBUG, "Network: Ethernet deactivated\n");
            }
            plugged = false;
            hasIP = false;
        }
    }
}

void Ethernet::verify(SystemData *data) {
    Configuration *cfg = data->cfg;
    /*
     * Verify network interface
     */
    verifyInterface(cfg);
    if (plugged && !hasIP) {
        setupIP(cfg);
    }
    /*
     * Update the Leds
     */
    if (plugged == false) {
        /*
         * When there is no network interface, cannot have a valid IP
         * address
         */
        hasIP = false;
        /*
         * Update the led
         */
        if (_leds != NULL) {
            _leds->off(Leds::NETWORK);
        }
    }
    else {
        /*
         * Network is active when there is a valid network interface
         * and assigned IP address
         */
        if (hasIP) {
            if (_leds != NULL) {
                _leds->on(Leds::NETWORK);
            }
        }
        else {
            if (_leds != NULL) {
                _leds->off(Leds::NETWORK);
            }
        }
    }
    /*
     * Take actions based on the status
     */
    if (!plugged) {
        setupInterface(cfg);
    }
    else {
        if (!hasIP) {
            setupIP(cfg);
        }
    }
}
