#include "UpdateCommand.h"
#include "Utils.h"
#include "defs.h"

#include <syslog.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netutils/base64.h>
#include <sys/boardctl.h>

void UpdateCommand::removeFiles(void) {
    /*
     * Open the root directory
     */
    DIR *pDir = opendir(FILEPATH);
    if (pDir == NULL) {
        syslog(LOG_ERR, "Transmission: Cannot open directory %s\n", FILEPATH);
        return;
    }
    /*
     * Scan files, removing the log files
     */
    struct dirent *pDirent;
    bool found = false;
    while (((pDirent = readdir(pDir)) != NULL) && (found == false)) {
        /*
         * Do not consider configuration files
         */
        if (strstr(pDirent->d_name,CFG_FILENAME) != NULL) {
            continue;
        }
        if (strstr(pDirent->d_name,CERT_FILENAME) != NULL) {
            continue;
        }
        if (strstr(pDirent->d_name,MODBUS_FILENAME) != NULL) {
            continue;
        }
        /*
         * Remove the file
         */
        syslog(LOG_DEBUG,"Removing loag file: %s\n",pDirent->d_name);
        std::string fileToRemove = FILEPATH;
        fileToRemove += pDirent->d_name;
        unlink(fileToRemove.c_str());
    }

    /*
     * Close the directory
     */
    closedir(pDir);
}

cJSON* UpdateCommand::execute(const cJSON *input, SystemData *data) {
    cJSON* output = NULL;
    std::string action;
    /*
     * Get the action to be performed in update process
     */
    Utils::extractJsonString("action",input,action);

    if (action == "start") {
        /*
         * Remove every log file saved on the dataflash
         */
        removeFiles();
        /*
         * Set the flag indicating the start of firmware update
         */
        updateMode = true;
        /*
         * Build output response
         */
        output = Utils::buildJsonOK("update",data->cfg->deviceId);
    }
    else if (action == "cancel") {
        /*
         * Remove the incomplete new firmware
         */
        removeFiles();
        /*
         * Set the flag indicating the end of firmware update
         */
        updateMode = false;
        /*
         * Build output response
         */
        output = Utils::buildJsonOK("update",data->cfg->deviceId);
    }
    else if (action == "sendfile") {
        /*
         * Extract the file content, codified in base64
         */
        std::string blockContent;
        size_t blockLen = 0;
        Utils::extractJsonString("block",input,blockContent);
        char *newBlock = (char*)base64_decode((unsigned char *)blockContent.c_str(), blockContent.size(),
                                    NULL, &blockLen);
        if (newBlock == NULL) {
            output = Utils::buildJsonERROR("update",data->cfg->deviceId,"Problem decoding block content");
        }
        else {
            /*
             * Save the content to the file
             */
            if (Utils::addBufferToFile((char*)FIRMWARE_FILE,newBlock,blockLen) == false) {
                output = Utils::buildJsonERROR("update",data->cfg->deviceId,"Problem saving block content");
            }
            else {
                /*
                 * Send a successful response
                 */
                output = Utils::buildJsonOK("update",data->cfg->deviceId);
            }
            /*
             * Release the allocated memory
             */
            free(newBlock);
        }
    }
    else if (action == "finish") {
        /*
         * Extract the MD5
         */
        std::string md5;
        Utils::extractJsonString("md5",input,md5);
        size_t md5Len = 0;
        uint8_t *md5_in = (uint8_t*)base64_decode((unsigned char *)md5.c_str(), md5.size(),
                                    NULL, &md5Len);
        if (md5_in == NULL) {
            output = Utils::buildJsonERROR("update",data->cfg->deviceId,"Problem decoding md5 field");
        }
        else if (md5Len != 16) {
            output = Utils::buildJsonERROR("update",data->cfg->deviceId,"Invalid md5 hash length provided");
        }
        else {
            /*
             * Calculate the MD5 from the saved file
             */
            uint8_t md5_out[16];
            Utils::calcMd5(FIRMWARE_FILE,md5_out);
            /*
             * For now, just informative
             */
            if (memcmp(md5_in,md5_out,16) != 0) {
                syslog(LOG_WARNING, "UpdateCommand: Different MD5 hashs in firmware file\n");
            }
        }
    }
    return output;
}