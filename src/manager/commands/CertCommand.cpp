#include "CertCommand.h"
#include "Utils.h"
#include "defs.h"

#include <syslog.h>
#include <netutils/base64.h>

cJSON* CertCommand::execute(const std::string& input, SystemData *data) {
    size_t certLen = 0;
    cJSON* output = NULL;
    /*
     * Value content is the certificate file encoded in base64.
     */
    char *newCert = (char*)base64_decode((unsigned char *)input.c_str(), input.size(),
                                    NULL, &certLen);
    if (newCert == NULL) {
        syslog(LOG_ERR,"Problem decoding certificate\n");
        output = Utils::buildJsonERROR("cert",data->cfg->deviceId,"Problem decoding certificate");
    }
    else {
        /*
         * Save the content to the file
         */
        if (Utils::saveBufferToFile((char*)CERTIFICATE_FILE,newCert,certLen) == false) {
            syslog(LOG_ERR,"Problem saving certificate file\n");
            output = Utils::buildJsonERROR("cert",data->cfg->deviceId,"Problem saving certificate");
        }
        else {
            /*
             * Send a successful response
             */
            output = Utils::buildJsonOK("cert",data->cfg->deviceId);
        }
    }

    free(newCert);

    return output;
}
