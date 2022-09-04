#include "ScanMapCommand.h"
#include "Utils.h"

#include <syslog.h>

cJSON* ScanMapCommand::execute(const cJSON *input, SystemData *data) {
    /*
     * In case of external memory problem, the gateway will be in
     * critical error state and the slave map won't be initialized.
     */
    if (data->slaveMap == NULL) {
        return Utils::buildJsonERROR("scanMap",data->cfg->deviceId,"MODBUS MAP not initialized");
    }
    /*
     * Value content is the same as modbus map configuration file.
     * So the procedure will be update in real time the map and then
     * update the internal file
     */
    data->slaveMap->process(input);
    data->slaveMap->save();
    /*
     * Send a successful response
     */
    return Utils::buildJsonOK("scanMap",data->cfg->deviceId);
}
