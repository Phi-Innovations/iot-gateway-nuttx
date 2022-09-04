#include "Utils.h"
#include "defs.h"

#include <syslog.h>
#include <netutils/md5.h>

bool Utils::fileExists(std::string path) {
    FILE *fp = NULL;

    fp = fopen(path.c_str(),"r");
    if (fp != NULL) {
        fclose(fp);
        return true;
    }

    return false;
}

bool Utils::extractJsonString(std::string name, const cJSON* input, std::string& out) {
    bool updated = false;

    const cJSON* field = cJSON_GetObjectItemCaseSensitive(input,name.c_str());
    if (field == NULL) {
        // syslog(LOG_ERR, "JSON message does not contain field: %s\n", name.c_str());
        return updated;
    }
	if (cJSON_IsString(field)) {
        out = field->valuestring;
        updated = true;
    }
    else {
        syslog(LOG_ERR, "JSON string type not found in field: %s\n", name.c_str());
    }

    return updated;
}

bool Utils::extractJsonInt(std::string name, const cJSON* input, int& out) {
    bool updated = false;

    const cJSON* field = cJSON_GetObjectItemCaseSensitive(input,name.c_str());
    if (field == NULL) {
        syslog(LOG_ERR, "JSON message does not contain field: %s\n", name.c_str());
        return updated;
    }
	if (cJSON_IsNumber(field)) {
        out = field->valueint;
        updated = true;
    }
    else {
        syslog(LOG_ERR, "JSON string type not found in field: %s\n", name.c_str());
    }

    return updated;
}

bool Utils::extractJsonBoolean(std::string name, const cJSON* input, int& out) {
    bool updated = false;

    const cJSON* field = cJSON_GetObjectItemCaseSensitive(input,name.c_str());
    if (field == NULL) {
        // syslog(LOG_ERR, "JSON message does not contain field: %s\n", name.c_str());
        return updated;
    }
	if (cJSON_IsString(field)) {
        out = atoi(field->valuestring);
        updated = true;
    }
    else {
        syslog(LOG_ERR, "JSON string type not found in field: %s\n", name.c_str());
    }

    return updated;
}

bool Utils::extractJsonChar(std::string name, const cJSON* input, char& out) {
    bool updated = false;

    const cJSON* field = cJSON_GetObjectItemCaseSensitive(input,name.c_str());
    if (field == NULL) {
        // syslog(LOG_ERR, "JSON message does not contain field: %s\n", name.c_str());
        return updated;
    }
	if (cJSON_IsString(field)) {
        out = field->valuestring[0];
        updated = true;
    }
    else {
        syslog(LOG_ERR, "JSON string type not found in field: %s\n", name.c_str());
    }

    return updated;
}

bool Utils::extractJsonHex(std::string name, const cJSON* input, int& out) {
    bool updated = false;

    const cJSON* field = cJSON_GetObjectItemCaseSensitive(input,name.c_str());
    if (field == NULL) {
        // syslog(LOG_ERR, "JSON message does not contain field: %s\n", name.c_str());
        return updated;
    }
	if (cJSON_IsString(field)) {
        out = std::stoi(field->valuestring, 0, 16);
        updated = true;
    }
    else {
        syslog(LOG_ERR, "JSON string type not found in field: %s\n", name.c_str());
    }

    return updated;
}

cJSON* Utils::buildJsonOK(std::string command, int deviceId) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command",command.c_str());
    cJSON_AddNumberToObject(root,"deviceId",deviceId);
    cJSON_AddStringToObject(root,"result","OK");
    return root;
}

cJSON* Utils::buildJsonERROR(std::string command, int deviceId, std::string message) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root,"command",command.c_str());
    cJSON_AddNumberToObject(root,"deviceId",deviceId);
    cJSON_AddStringToObject(root,"result","ERROR");
    cJSON_AddStringToObject(root,"description",message.c_str());
    return root;
}

bool Utils::saveBufferToFile(char *path, char *data, size_t len) {
    bool ret = false;
    /*
     * Open file to save output
     */
    FILE *fp = NULL;
    fp = fopen(path,"w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Problem file for writing: %s\n", path);
        return false;
    }
    
    /*
     * Generating the string and saving to the file
     */
    size_t nwrite = fwrite(data,1,len,fp);
    if (nwrite < 0) {
        syslog(LOG_ERR, "Problem writing data to file: %s\n",path);
    }
    else if (nwrite != len) {
        syslog(LOG_WARNING, "File %s not written completely\n",path);
        ret = true;
    }
    else {
        /* Write success */
        ret = true;
    }

    /*
     * Finishing
     */
    fclose(fp);

    return ret;
}

bool Utils::addBufferToFile(char *path, char *data, size_t len) {
    bool ret = false;
    /*
     * Open file to save output
     */
    FILE *fp = NULL;
    fp = fopen(path,"a");
    if (fp == NULL) {
        syslog(LOG_ERR, "Problem file for writing: %s\n", path);
        return false;
    }
    
    /*
     * Generating the string and saving to the file
     */
    size_t nwrite = fwrite(data,1,len,fp);
    if (nwrite < 0) {
        syslog(LOG_ERR, "Problem writing data to file: %s\n",path);
    }
    else if (nwrite != len) {
        syslog(LOG_WARNING, "File %s not written completely\n",path);
        ret = true;
    }
    else {
        /* Write success */
        ret = true;
    }

    /*
     * Finishing
     */
    fclose(fp);

    return ret;
}

char* Utils::loadBufferFromFile(char *path, size_t *len) {
    /*
     * Open the configuration file
     */
    FILE *fp;
    fp = fopen(path,"r");
    if (fp == NULL) {
        syslog(LOG_ERR, "Unable to open file: %s\n", path);
        return NULL;
    }

    /*
     * Get the file size
     */
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /*
     * Allocate memory for reading data
     */
    char *data = (char*)malloc(fileSize + 1);
    if (data == NULL) {
        syslog(LOG_ERR, "Problem initializing memory for reading file: %s\n", path);
        fclose(fp);
        return NULL;
    }
    memset(data,0,fileSize+1);

    /*
     * Read file content
     */
    size_t nread = fread(data,1,fileSize,fp);
    if (nread != fileSize) {
        syslog(LOG_ERR, "Problem reading file: %s\n", path);
        free(data);
        fclose(fp);
        return NULL;
    }

    /*
     * Close the file
     */
    fclose(fp);

    /*
     * Return the created buffer
     */
    *len = fileSize;
    return data;
}

void Utils::calcMd5(char *path, uint8_t *md5) {
    unsigned char block[FW_UPDATE_BLOCK_LEN];
    /*
     * Open the configuration file
     */
    FILE *fp;
    fp = fopen(path,"r");
    if (fp == NULL) {
        syslog(LOG_ERR, "Unable to open file: %s\n", path);
        return;
    }

    /*
     * Get the file size and the number of blocks
     */
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    int nbBlocks = fileSize / FW_UPDATE_BLOCK_LEN;

    MD5_CTX ctx;
    md5_init(&ctx);

    /*
     * Scan the file in blocks, updating the MD5 calculation
     */
    fseek(fp, 0, SEEK_SET);
    int err = 0;
    for(int i=0;((i<nbBlocks)&&(err==0));i++) {
        memset(block,0,sizeof(block));
        /*
         * Read block from the file
         */
        size_t nread = fread(block,1,FW_UPDATE_BLOCK_LEN,fp);
        if (nread != FW_UPDATE_BLOCK_LEN) {
            syslog(LOG_ERR, "Problem reading file: %s\n", path);
            err = -1;
        }
        else {
            /*
             * Update the MD5 calculation
             */
            md5_update(&ctx,block,FW_UPDATE_BLOCK_LEN);
        }
    }
    /*
     * Check for a last block
     */
    if ((err == 0) && (fileSize % FW_UPDATE_BLOCK_LEN)) {
        memset(block,0,sizeof(block));
        /*
         * Read block from the file
         */
        size_t nread = fread(block,1,FW_UPDATE_BLOCK_LEN,fp);
        if (nread != FW_UPDATE_BLOCK_LEN) {
            syslog(LOG_ERR, "Problem reading file: %s\n", path);
            err = -1;
        }
        else {
            /*
             * Update the MD5 calculation
             */
            md5_update(&ctx,block,FW_UPDATE_BLOCK_LEN);
        }
    }
    /*
     * Finish the calculation and get the hash
     */
    if (err == 0) {
        md5_final(md5,&ctx);
    }
}

std::string Utils::OperationMode(int mode) {
    std::string output;

    switch (mode) {
    case GW_FUNCTION_MODBUS_DATALOGGER:
        output = "MODBUS_DATALOGGER";
        break;
    case GW_FUNCTION_MODBUS_GATEWAY:
        output = "MODBUS_GATEWAY";
        break;
    default:
        output = "UNKNOWN: " + std::to_string(mode);
        break;
    }

    return output;
}

std::string Utils::TransmissionMode(int mode) {
    std::string output;

    switch (mode) {
    case TRANSMISSION_MODE_CONNECTED:
        output = "CONNECTED";
        break;
    case TRANSMISSION_MODE_STANDARD:
        output = "STANDARD";
        break;
    case TRANSMISSION_MODE_INDIVIDUAL:
        output = "INDIVIDUAL";
        break;
    default:
        output = "UNKNOWN: " + std::to_string(mode);
        break;
    }

    return output;
}

std::string Utils::PayloadType(int type) {
    std::string output;

    switch(type) {
    case PAYLOAD_TYPE_STD:
        output = "STANDARD";
        break;
    case PAYLOAD_TYPE_KRON:
        output = "KRON";
        break;
    default:
        output = "UNKNOWN: " + std::to_string(type);
        break;
    }

    return output;
}
