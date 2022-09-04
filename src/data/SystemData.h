#pragma once

#include "Configuration.h"
#include "SlaveMap.h"
#include "Status.h"

class SystemData {
private:
    int formatDisk(void);
    int flash_eraseall(FAR const char *driver);

    int setupFilesystem(bool isReset);
public:
    Configuration   *cfg = NULL;
    SlaveMap        *slaveMap = NULL;

    SystemData(Status *_status);
    ~SystemData();

    bool reset(void);
};
