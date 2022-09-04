#include "SystemData.h"

#include <syslog.h>
#include <sys/mount.h>
#include <nuttx/mtd/mtd.h>
#include <fsutils/flash_eraseall.h>
#include <fsutils/mksmartfs.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef USE_SMARTFS
#define FS_DEVICE "/dev/smart0"
#define FS_TYPE "smartfs"
#else
#define FS_DEVICE "/dev/mtd"
#define FS_TYPE "littlefs"
#endif
#define FS_MOUNTPOINT "/mnt/disk"

SystemData::SystemData(Status *_status) {
  /** Flavio Alves: let here to restore configuration */
  // formatDisk();
  /*
   * Setting up the filesystem
   */
  if (setupFilesystem(false) < 0) {
      syslog(LOG_ERR, "Problem setting filesystem\n");
      /*
       * Update the status structure, indicating error
       */
      _status->state = STATUS_CRITICAL_ERROR;
  }
  /*
   * Initialize local structures
   */
  cfg = new Configuration();
  /*
   * Do not load slave map in case of critical error
   */
  if (_status->state == STATUS_GENERAL_ACTIVE) {
    slaveMap = new SlaveMap();
  }
}

SystemData::~SystemData() {
    if (cfg != NULL) {
        delete cfg;
        cfg = NULL;
    }
    if (slaveMap != NULL) {
        delete slaveMap;
        slaveMap = NULL;
    }
}

int SystemData::setupFilesystem(bool isReset) {
    /*
     * First mount the filesystem
     */
    syslog(LOG_INFO, "Mounting " FS_TYPE " filesystem (driver " FS_DEVICE ") at " FS_MOUNTPOINT "\n");
    int ret = 0;
    if (isReset) {
      ret = mount(std::string(FS_DEVICE).c_str(), std::string(FS_MOUNTPOINT).c_str(), 
                        std::string(FS_TYPE).c_str(), 0, "autoformat");
    }
    else {
      ret = mount(FS_DEVICE,FS_MOUNTPOINT,FS_TYPE, 0, NULL);
    }
    if (ret < 0) {
        syslog(LOG_ERR, "Problem mounting filesystem: %d (%d): Formating the disk\n", ret, errno);
        ret = formatDisk();
        if (ret == 0) {
            /*
             * In case of success, try again
             */
#ifdef USE_SMARTFS
            ret = mount(std::string(FS_DEVICE).c_str(), std::string(FS_MOUNTPOINT).c_str(), 
                        std::string(FS_TYPE).c_str(), 0, NULL);
#else
            ret = mount(std::string(FS_DEVICE).c_str(), std::string(FS_MOUNTPOINT).c_str(), 
                        std::string(FS_TYPE).c_str(), 0, "autoformat");
#endif
        }
    }

    if (ret < 0) {
        syslog(LOG_ERR, "Could not mount filesystem\n");
        return -1;
    }

    syslog(LOG_INFO, "Mount successful\n");

    return 0;
}

int SystemData::formatDisk(void) {
    /*
     * First remove completely the contents of the memory
     */
    int ret = flash_eraseall(std::string(FS_DEVICE).c_str());
    if (ret < 0) {
        syslog(LOG_ERR, "Problem erasing the disk\n");
        return -1;
    }

#ifdef USE_SMARTFS
    /*
     * Formatting the disk
     */
    ret = mksmartfs(std::string(FS_DEVICE).c_str(),1024);
    if (ret < 0) {
        syslog(LOG_ERR, "Error formatting the disk\n");
        return -1;
    }
#endif

    return 0;
}

/*
 * TODO: Replace for the correct execution from fsutils
 */
int SystemData::flash_eraseall(FAR const char *driver)
{
  int errcode;
  int fd;
  int ret;

  /* Open the block driver */

  fd = open(driver, O_RDONLY);
  if (fd < 0)
    {
      errcode = errno;
      syslog(LOG_ERR, "ERROR: Failed to open '%s': %d\n", driver, errcode);
      ret = -errcode;
    }
  else
    {
      /* Invoke the block driver ioctl method */

      ret = ioctl(fd, MTDIOC_BULKERASE, 0);
      if (ret < 0)
        {
          errcode = errno;
          syslog(LOG_ERR, "ERROR: MTD ioctl(%04x) failed: %d\n", MTDIOC_BULKERASE, errcode);
          ret = -errcode;
        }

      /* Close the block driver */

     close(fd);
    }

  return ret;
}

bool SystemData::reset(void) {
  syslog(LOG_DEBUG, "SystemData: unmounting filesystem\n");
  
  if (umount(FS_MOUNTPOINT) < 0) {
    syslog(LOG_ERR, "SystemData: problem umounting filesystem\n");
    return false;
  }

  syslog(LOG_DEBUG, "SystemData: formatting memory\n");
  if (formatDisk() < 0) {
    syslog(LOG_ERR, "SystemData: problem formatting the memory\n");
    return false;
  }

  syslog(LOG_DEBUG, "SystemData: reinitializing the memory\n");
  if (setupFilesystem(true) < 0) {
    syslog(LOG_ERR, "SystemData: problem initializing the memory\n");
    return false;
  }

  syslog(LOG_DEBUG, "SystemData: initialize default values and save to memory\n");
  cfg->initializeDefaultValues();
  if (cfg->save() < 0) {
    syslog(LOG_ERR, "SystemData: problem saving configuration file into the memory\n");
    return false;
  }

  syslog(LOG_DEBUG, "SystemData: initialize certificate and save to memory\n");
  if (cfg->createCertificate() < 0) {
    syslog(LOG_ERR, "SystemData: problem saving certificate file into the memory\n");
    return false;
  }

  syslog(LOG_DEBUG, "SystemData: initialize modbus map to memory\n");
  if (slaveMap->create() < 0) {
    syslog(LOG_ERR, "SystemData: problem saving modbus map file into the memory\n");
    return false;
  }

  return true;
}
