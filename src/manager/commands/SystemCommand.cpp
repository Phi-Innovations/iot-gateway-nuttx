#include "SystemCommand.h"
#include "Utils.h"

#include <syslog.h>
#include <sys/boardctl.h>

cJSON* SystemCommand::execute(const std::string& input, SystemData *data) {
    
    cJSON* output = NULL;

    if (input == "reset") {
        boardctl(BOARDIOC_RESET, EXIT_SUCCESS);
        /*
         * It should not return. If it happens, an error occurred
         */
        output = Utils::buildJsonERROR("system",data->cfg->deviceId,"Problem while rebooting the gateway");
    }
    else if (input == "format") {
        /*
         * Format the whole disk (dataflash)
         */
        if (data->reset() == true) {
            output = Utils::buildJsonOK("system",data->cfg->deviceId);
        }
        else {
            output = Utils::buildJsonERROR("system",data->cfg->deviceId,"Problem while resetting the gateway's memory");
        }
    }

    return output;
}
