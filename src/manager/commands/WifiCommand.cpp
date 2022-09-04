#include "WifiCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* WifiCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonString("ip",input,data->cfg->net_wifi.ipAddr);
    Utils::extractJsonString("netmask",input,data->cfg->net_wifi.netmask);
    Utils::extractJsonString("gateway",input,data->cfg->net_wifi.gateway);
    Utils::extractJsonString("dns",input,data->cfg->net_wifi.dns);
    Utils::extractJsonBoolean("dhcp",input,data->cfg->net_wifi.isDHCP);
    Utils::extractJsonString("ssid",input,data->cfg->wifi.ssid);
    Utils::extractJsonString("password",input,data->cfg->wifi.passwd);

    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("wifi",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("wifi",data->cfg->deviceId);
    }
    
    return output;
}