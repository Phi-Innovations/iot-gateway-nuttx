#pragma once

#include <stdint.h>
#include <string>

struct NetworkInfo{
	int isDHCP;
	std::string ipAddr;
	std::string netmask;
	std::string gateway;
	std::string dns;
	std::string macAddress;
};
