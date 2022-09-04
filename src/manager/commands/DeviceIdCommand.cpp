#include "DeviceIdCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* DeviceIdCommand::execute(const cJSON *input, SystemData *data) {
    int oldDeviceId = data->cfg->deviceId;
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonInt("newDeviceId",input,data->cfg->deviceId);

    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("deviceId",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("deviceId",oldDeviceId);
    }

    return output;
}
