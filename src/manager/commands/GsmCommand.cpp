#include "GsmCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* GsmCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonString("gsm1apn",input,data->cfg->simcard[0].apn);
    Utils::extractJsonString("gsm1user",input,data->cfg->simcard[0].user);
    Utils::extractJsonString("gsm1pwd",input,data->cfg->simcard[0].pwd);
    Utils::extractJsonString("gsm2apn",input,data->cfg->simcard[1].apn);
    Utils::extractJsonString("gsm2user",input,data->cfg->simcard[1].user);
    Utils::extractJsonString("gsm2pwd",input,data->cfg->simcard[1].pwd);
    Utils::extractJsonInt("gsmDefault",input,data->cfg->usedSimNb);

    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("gsm",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("gsm",data->cfg->deviceId);
    }

    return output;
}