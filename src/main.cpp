#include <stdio.h>
#include "PhiGateway.h"
#include "data/SystemData.h"
#include "data/Status.h"
#include "manager/Manager.h"
#include "MqttClient.h"
#include "Tls.h"

#include <nuttx/config.h>

extern "C"
{
	int phigw_main(void) {

		syslog(LOG_INFO, "Starting PHI-Gateway application\n");

		Status		*status = new Status();
		SystemData	*data = new SystemData(status);
		Manager		*manager = new Manager(data, status);
		/*
		 * In case of critical error, the communication should not work
		 */
		MqttClient	*mqtt = NULL;
		if (status->state == STATUS_GENERAL_ACTIVE) {
			mqtt = new MqttClient(manager);
		}
		PhiGateway	*gw = new PhiGateway(data, status, mqtt, manager);

		gw->run();
		
		syslog(LOG_INFO, "End of PHI-Gateway execution\n");

		delete status;
		delete manager;
		delete data;
		delete gw;

		return 0;
	}
}

