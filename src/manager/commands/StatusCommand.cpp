#include "StatusCommand.h"
#include "Utils.h"
#include "defs.h"
#include <syslog.h>

cJSON* StatusCommand::execute(Status *status, SystemData *data) {
    syslog(LOG_DEBUG, "Starting status command\n");

    cJSON* output = buildStatusResponse(status, data->cfg);

    return output;
}

cJSON* StatusCommand::buildStatusResponse(Status *status, Configuration *cfg) {

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command","status");
    cJSON_AddNumberToObject(root,"deviceId",cfg->deviceId);
    cJSON_AddStringToObject(root,"result","OK");

    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value,"version",status->version);
    cJSON_AddNumberToObject(value,"state",status->state);
    cJSON_AddNumberToObject(value,"networkState",status->networkState);
    cJSON_AddStringToObject(value,"ip",status->ip.c_str());
    cJSON_AddNumberToObject(value,"nbRegisters",status->nbStoreRegisters);
    cJSON_AddBoolToObject(value,"diskFull",status->diskFull);
    cJSON_AddItemToObject(root,"value",value);

    return root;
}
