#pragma once

#include <string>
#include <stdint.h>
#include "netutils/cJSON.h"

class Utils {
public:
    static bool fileExists(std::string path);
    static bool extractJsonString(std::string name, const cJSON* input, std::string& out);
    static bool extractJsonInt(std::string name, const cJSON* input, int& out);
    static bool extractJsonBoolean(std::string name, const cJSON* input, int& out);
    static bool extractJsonChar(std::string name, const cJSON* input, char& out);
    static bool extractJsonHex(std::string name, const cJSON* input, int& out);
    static cJSON* buildJsonOK(std::string command, int deviceId);
    static cJSON* buildJsonERROR(std::string command, int deviceId, std::string message);
    static bool saveBufferToFile(char *path, char *data, size_t len);
    static bool addBufferToFile(char *path, char *data, size_t len);
    static char* loadBufferFromFile(char *path, size_t *len);
    static void calcMd5(char *path, uint8_t *md5);

    static std::string PayloadType(int type);
    static std::string TransmissionMode(int mode);
    static std::string OperationMode(int mode);
};
