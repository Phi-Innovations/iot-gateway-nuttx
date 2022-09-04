#include "ScanGeneralCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* ScanGeneralCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonInt("payloadType",input,data->cfg->payloadType);
    Utils::extractJsonInt("transmissionMode",input,data->cfg->transmissionMode);
    if (Utils::extractJsonInt("scanInterval",input,data->cfg->scanInterval) == true) {
        /* Convert data from minutes to seconds */
        data->cfg->scanInterval *= 60;
    }
    Utils::extractJsonInt("payloadType",input,data->cfg->payloadType);
    if (Utils::extractJsonInt("sendInterval",input,data->cfg->sendInterval) == true) {
        /* Convert data from minutes to seconds */
        data->cfg->sendInterval *= 60;
    }
    Utils::extractJsonInt("cmdInterval",input,data->cfg->cmdInterval);
    Utils::extractJsonInt("operationMode",input,data->cfg->operationMode);
    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("scanGeneral",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("scanGeneral",data->cfg->deviceId);
    }

    return output;
}
