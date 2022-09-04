#include "OperationCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* OperationCommand::execute(const cJSON *input, SystemData *data) {    
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonInt("mode",input,data->cfg->operationMode);

    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("operation",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("operation",data->cfg->deviceId);
    }

    return output;
}
