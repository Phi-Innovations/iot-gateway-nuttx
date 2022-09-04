#include "MqttCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* MqttCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * For now, just discard the field not found
     */
    Utils::extractJsonString("serverAddress",input,data->cfg->mqtt.server.address);
    Utils::extractJsonInt("serverPort",input,data->cfg->mqtt.server.port);
    Utils::extractJsonString("clientId",input,data->cfg->mqtt.cliendId);
    Utils::extractJsonString("username",input,data->cfg->mqtt.username);
    Utils::extractJsonString("password",input,data->cfg->mqtt.password);
    Utils::extractJsonString("pubTopic",input,data->cfg->mqtt.pubTopic);
    Utils::extractJsonString("rspTopic",input,data->cfg->mqtt.rspTopic);
    Utils::extractJsonString("cmdTopic",input,data->cfg->mqtt.cmdTopic);
    Utils::extractJsonInt("connectionMode",input,data->cfg->connectionMode);
    Utils::extractJsonInt("useTls",input,data->cfg->mqtt.useTls);
    Utils::extractJsonInt("tlsAuthMode",input,data->cfg->mqtt.tlsAuthMode);

    /*
     * Saving updated parameter to disk
     */
    cJSON* output = NULL;
    if (data->cfg->save() < 0) {
        output = Utils::buildJsonERROR("mqtt",data->cfg->deviceId,"Could not update configuration file");
    }
    else {
        output = Utils::buildJsonOK("mqtt",data->cfg->deviceId);
    }

    return output;
}
