#include "PhiGateway.h"
#include "manager/Manager.h"
#include "data/SystemData.h"
#include "Utils.h"
#include "network/Ethernet.h"

#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <netutils/netlib.h>
#include <dirent.h>

#include <chrono>

#define CYCLE_TIME        10 // seconds
#define duration_msec(a)  std::chrono::duration_cast<std::chrono::milliseconds>(a).count()
#define timeNow()         std::chrono::system_clock::now()

PhiGateway::PhiGateway(SystemData *_data, Status *_status, MqttClient *_mqtt, Manager *_manager) :
                  data(_data), status(_status), mqttClient(_mqtt), manager(_manager) {
  /*
   * Initialize internal components
   */
  leds = new Leds();
  capture = new Capture(data, leds, status);
  /*
   * Initialize the structure according to the technology
   */
  switch(data->cfg->connectionMode) {
    case CONNECTION_TYPE_ETHERNET:
      network = (NetworkIF*)(new Ethernet(data, leds));
      break;
    default:
      syslog(LOG_ERR,"PhiGateway: Unknown connection mode: %d\n",data->cfg->connectionMode);
      break;
  }

  transmission = new Transmission(data,mqttClient, leds);

  ready = true;
}

PhiGateway::~PhiGateway() {
  if (leds != NULL) {
    delete leds;
  }
  if (capture != NULL) {
    delete capture;
  }
  if (network != NULL) {
    delete network;
  }
  if (transmission != NULL) {
    delete transmission;
  }
}

void PhiGateway::showBaseConfig(void) {
  /*
   * Showing basic operation instructions in log
   */
  syslog(LOG_INFO,"Operation mode: %s\n",Utils::OperationMode(data->cfg->operationMode).c_str());
  syslog(LOG_INFO,"Transmission mode: %s\n",Utils::TransmissionMode(data->cfg->transmissionMode).c_str());
}

int PhiGateway::run(void) {
  std::chrono::time_point<std::chrono::system_clock> start;

    if (ready) {
        
        syslog(LOG_DEBUG, "Running application\n");

        showBaseConfig();

        /*
         * Starting main loop
         */
        while(true) {
          /*
           * Capture execution starting time
           */
          start = timeNow();
          /*
           * Verify the network. In case of error state,
           * do not execute
           */
          if (status->state == STATUS_GENERAL_ACTIVE) {
            // syslog(LOG_DEBUG, "PhiGateway: Network\n");
            network->verify(data);
          }          
          /*
           * Manage configuration messages. Accept external
           * commands even when the system is in error state
           */
          // syslog(LOG_DEBUG, "PhiGateway: Manager\n");
          manager->run();
          /*
           * In case of firmware update transfer or error state
           * the firmware operations are blocked
           * TODO: change the manager update mode to a phi-gateway
           * update state, in status component
           */
          if ((manager->isUpdateMode() == false) && 
                (status->state == STATUS_GENERAL_ACTIVE)) {
            /*
             * Execute modbus scan procedure
             */
            // syslog(LOG_DEBUG, "PhiGateway: Capture\n");
            capture->scan(data);
            
            if (NetworkIF::isPlugged() == true) {
              /*
               * Execute modbus send operation
               */
              // syslog(LOG_DEBUG, "PhiGateway: Transmission\n");
              transmission->run();
              /*
               * Process MQTT
               */
              // syslog(LOG_DEBUG, "PhiGateway: mqtt sync\n");
              mqttClient->sync();
              /*
               * Evaluate MQTT Commands, when received
               */
              // syslog(LOG_DEBUG, "PhiGateway: mqtt commands\n");
              processMqttCommands();
            }
            else {
              /*
               * Stop the MQTT communication in case of abrupt
               * network communication
               */
              if (mqttClient->isConnected()) {
                mqttClient->stop();
              }
            }
          }
          /*
           * Status
           */
          // syslog(LOG_DEBUG, "PhiGateway: Status\n");
          updateStatus();
          /*
           * Wait for the end of the cycle.
           * The time used so far is calculated in milliseconds. The cycle time
           * is in seconds and the wait routine is in microseconds. Conversions
           * must be performed.
           * 
           * The wait cycle happens only for datalogger mode
           */
          // syslog(LOG_DEBUG, "PhiGateway: Wait\n");
          if (data->cfg->operationMode == GW_FUNCTION_MODBUS_DATALOGGER) {
            int wait = (CYCLE_TIME * 1000) - (int)duration_msec(timeNow() - start);
            if (wait > 0) {
              usleep(wait * 1000);
            }
          }
        }
    }
    else {
        syslog(LOG_ERR, "Could not start PHI-Gateway\n");
    }

    return 0;
}

void PhiGateway::updateStatus(void) {
  /*
   * Read current IP address
   */
  struct in_addr addr;
  netlib_get_ipv4addr(NETWORK_ETHERNET_IFACE,&addr);
  status->ip = inet_ntoa(addr);
  /*
   * Get the network state
   */
  status->networkState = network->getState();
  /*
   * Set the led based on the current value of the
   * Phi-Gateway state
   */
  if (status->state == STATUS_GENERAL_ERROR) {
      leds->on(Leds::ERROR);
  }
  else {
      leds->off(Leds::ERROR);
  }
  /*
   * Calculate and assing the number of stored registers
   */
  status->nbStoreRegisters = capture->getNbRegisters();
  status->diskFull = capture->isDiskFull();
}

void PhiGateway::processMqttCommands(void) {

  if (mqttClient == NULL) {
      syslog(LOG_ERR,"MQTT client not initialized\n");
      return;
  }

  /*
   * Read each payload from the queue and evaluate it
   */
  bool finished = false;
  while(finished == false) {
    std::string cmd = manager->getMqttCommand();
    if (cmd.empty() == true) {
      finished = true;
      continue;
    }
    /*
     * Evaluate the command
     */
    cJSON *output = manager->evaluateMessage(cmd);
    /*
     * Send the command
     */
    if (output != NULL) {
      char *resp = cJSON_PrintUnformatted(output);
      if (resp != NULL) {
        /*
         * Publish the response
         */
        mqttClient->publish(data->cfg->mqtt.rspTopic,resp,strlen(resp));
        /*
         * Clear the buffer
         */
        free(resp);
      }
      /*
       * Clear the json output
       */
      free(output);
    }
    /*
     * Get the next command
     */
    cmd = manager->getMqttCommand();
  }
}
