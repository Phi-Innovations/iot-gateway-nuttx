#include "EthernetCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* EthernetCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonString("ip",input,data->cfg->net.ipAddr);
    Utils::extractJsonString("netmask",input,data->cfg->net.netmask);
    Utils::extractJsonString("gateway",input,data->cfg->net.gateway);
    Utils::extractJsonString("dns",input,data->cfg->net.dns);
    Utils::extractJsonBoolean("dhcp",input,data->cfg->net.isDHCP);
    Utils::extractJsonString("mac",input,data->cfg->net.macAddress);

    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("ethernet",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("ethernet",data->cfg->deviceId);
    }

    return output;
}