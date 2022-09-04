#pragma once

#include <string>

#include "Connection.h"

struct MqttInfo {
	int 		useTls;
	int			tlsAuthMode;
	int			cmdCallInterval;
	Connection	server;
	std::string	cliendId;
	std::string	pubTopic;
	std::string	cmdTopic;
	std::string	rspTopic;
	std::string	lwTopic;
	std::string	username;
	std::string	password;
};
