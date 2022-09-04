#include "Configuration.h"
#include "ConfigData.h"
#include "defs.h"
#include "version.h"
#include "Utils.h"

#include <syslog.h>

#include <string>

#define BASE_CERTIFICATE \
		"-----BEGIN CERTIFICATE-----\r\n" \
		"MIIEFzCCAv+gAwIBAgIUb6dFLE7udphCIIJVpQsJYmbyhKswDQYJKoZIhvcNAQEL\r\n" \
		"BQAwgZoxCzAJBgNVBAYTAkJSMQ8wDQYDVQQIDAZQYXJhbmExETAPBgNVBAcMCEN1\r\n" \
		"cml0aWJhMRcwFQYDVQQKDA5Ucm94IGRvIEJyYXNpbDEPMA0GA1UECwwGVFgtSU9U\r\n" \
		"MQ8wDQYDVQQDDAZUWC1JT1QxLDAqBgkqhkiG9w0BCQEWHWpvcmdlLnNpbHZhQHRy\r\n" \
		"b3hicmFzaWwuY29tLmJyMB4XDTIwMDYyNjEyNTI1NFoXDTQ3MTExMjEyNTI1NFow\r\n" \
		"gZoxCzAJBgNVBAYTAkJSMQ8wDQYDVQQIDAZQYXJhbmExETAPBgNVBAcMCEN1cml0\r\n" \
		"aWJhMRcwFQYDVQQKDA5Ucm94IGRvIEJyYXNpbDEPMA0GA1UECwwGVFgtSU9UMQ8w\r\n" \
		"DQYDVQQDDAZUWC1JT1QxLDAqBgkqhkiG9w0BCQEWHWpvcmdlLnNpbHZhQHRyb3hi\r\n" \
		"cmFzaWwuY29tLmJyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4AW8\r\n" \
		"Es+GFxlM0fmqtUvGnqb+O6IuzBf79jYt3s80Zm1R7UBRQBd1E1TLMojxcU4sdEdK\r\n" \
		"Cfo05y1TIJFlIMLygaWO41CLknfdWuE8g03n4gR6RXMWukbYlw5kFmfuYum6U+FG\r\n" \
		"5fWnifIpbDPrUJ4FnR6ZTPSSs9lXhaLK6yNGtHgo1PgnWUGCVXumfqfPjhUcSQLV\r\n" \
		"nEnzccYx3y8XCo/LMdRWgnHHAd7A2BPTciN5t3qqCjycxkfbF1xjehzyPX4Pi5s2\r\n" \
		"Q12wZJXF2YxKVwiAuKXrdm3cwsNB5baLXFHhR3n5FjZGhG1jQX+moHIrXKfMYXec\r\n" \
		"ElyjXKy92AE+W54rhQIDAQABo1MwUTAdBgNVHQ4EFgQUE8BXhZS0CXdNDRypSWUy\r\n" \
		"CehvCxIwHwYDVR0jBBgwFoAUE8BXhZS0CXdNDRypSWUyCehvCxIwDwYDVR0TAQH/\r\n" \
		"BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAQkfSeQBoqwEkl284qWEhR6xG1A0K\r\n" \
		"yiGDWwe3V/bsZqnIcOI1j1XCRBPcaODe/VcHx+Lw8qci3XGxYDUlE8jDw7cEhBPG\r\n" \
		"ihkOLy7qzI2fKE8TeCEDzxPFTIusuc/m8oGMd++6DV03KiYYENnrsqAhuhWEvoPn\r\n" \
		"v9RfQOqjVjsZi0+q0e/dGf4k9PqthTFLxFi2QJHRUT324IIw3bEGxs8rMoCl4SJv\r\n" \
		"nUk3nOfmfE+3xHcIz45uI1s1dxZmZq230gAjGku7kxMzF8xe6S1/wGfrzC2kaKJy\r\n" \
		"XQAtd85Sh1/q9j7scVQvOG3pqvNbmKzbNj6e8+KlKtHRuI8kFd01j/y+2w==\r\n" \
		"-----END CERTIFICATE-----"

Configuration::Configuration() {
    if (!Utils::fileExists(CONFIG_FILE)) {
        syslog(LOG_WARNING, "Could not find configuration file. Creating one\n");
        initializeDefaultValues();
        save();
    }
	else {
		syslog(LOG_INFO, "Loading configuration\n");
		if (load() < 0) {
			syslog(LOG_WARNING, "Problem loading configuration. Initializing default\n");
			initializeDefaultValues();
		}
	}

	if (!Utils::fileExists(CERTIFICATE_FILE)) {
		syslog(LOG_WARNING, "Could not find certificate file. Creating one\n");
        if (createCertificate() == true) {
			syslog(LOG_DEBUG, "Certificate file created\n");
		}    
	}
}

void Configuration::initializeDefaultValues(void) {
	/*
	 * Operacao: padrao datalogger
	 */
	operationMode = GW_FUNCTION_MODBUS_DATALOGGER;
	cmdInterval = 5;	/* minutos */
	modbusEnabled = 1;
#if MODE_CONFIGS_KRON
	payloadType = PAYLOAD_TYPE_KRON;
	independentMode = 1;
	scanInterval = 5 * 60; /* seconds */
	sendInterval = 15 * 60; /* seconds */
#else
	scanInterval = 1 * 60; /* seconds */
	sendInterval = 2 * 60; /* seconds */
	payloadType = PAYLOAD_TYPE_KRON;
	transmissionMode = TRANSMISSION_MODE_INDIVIDUAL;
#endif
	inputEnabled = 0;
#if MODE_CONFIGS_KRON
	inputScanInterval = 5;	/* minutos */
	inputSendInterval = 15;	/* minutos */
#else
	inputScanInterval = 1;	/* minutos */
	inputSendInterval = 3;	/* minutos */
#endif
	inputHasExpansion = 0;
	/*
	 * Modbus
	 */
	modbus.baudrate = 9600;
	modbus.parity = 'N';
	modbus.dataBit = 8;
	modbus.stopBits = 2;
	modbus.slaveAddr = 1;
	modbus.tcpPort = 1502;
#if MODE_CONFIGS_KRON
	modbus.baseAddress = 30001;
#else
	modbus.baseAddress = 30001; // KRON
#endif
	modbusNbRetries = 2;
	modbusDelayBetweenReads = 2000;

	/* Atualmente a estrutura foi dimensionada para comportar registros no
	 * limite de 128 bytes de tamanho para armazenamento confiavel na dataflash
	 * Entao a estrutura e organizada da seguinte forma:
	 * - timestamp (8 bytes)
	 * - tabela (59 words)
	 * - crc (2 bytes)
	 * Esse parametro pode ser parametrizavel de forma a limitar a quantidade
	 * de registros em ate 59 posicoes da tabela modbus
	 *
	 * Esse parametro e importante para configurar o payload de transmissao
	 * de dados de datalog. Internamente a tabela e armazenada em seu tamanho
	 * maximo
	 */
	/*
	 * Configuracoes de rede ethernet
	 */
#if MODE_CONFIGS_KARCHER
	net.isDHCP = 0;
	net.ipAddr[0] = 192;
	net.ipAddr[1] = 168;
	net.ipAddr[2] = 0;
	net.ipAddr[3] = 20;
	net.netmask[0] = 255;
	net.netmask[1] = 255;
	net.netmask[2] = 255;
	net.netmask[3] = 0;
	net.gateway[0] = 192;
	net.gateway[1] = 168;
	net.gateway[2] = 0;
	net.gateway[3] = 1;
	net.dns[0] = 8;
	net.dns[1] = 8;
	net.dns[2] = 8;
	net.dns[3] = 8;
#else
	net.isDHCP = true;
	/*
	 * DNS nao e fornecido pelo DHCP
	 */
    net.dns = "8.8.8.8";
#endif
	/*
	 * MAC Address sempre fornecido
	 */
    net.macAddress = "00:80:e1:00:00:00";
	/*
	 * Configuracoes de rede Wifi
	 */
	net_wifi.isDHCP = true;
    net_wifi.ipAddr = "10.1.1.30";
    net_wifi.netmask = "255.255.255.0";
    net_wifi.gateway = "10.1.1.1";
    net_wifi.dns = "8.8.8.8";
    wifi.ssid = "";
    wifi.passwd = "";
	/*
	 * Informacoes do equipamento
	 */
	deviceId = 1;
	connectionMode = CONNECTION_TYPE_ETHERNET;
    prod.serialNumber = "1";
	/*
	 * Celular
	 */
	usedSimNb = 1;
    SimCardInfo item0;
	item0.apn = "zap.vivo.com.br";
	item0.user = "vivo";
	item0.pwd = "vivo";
	item0.direct_mode = 1;
	item0.connId = 1;
    simcard.push_back(item0);
    SimCardInfo item1;
	item1.apn = "zap.vivo.com.br";
	item1.user = "vivo";
	item1.pwd = "vivo";
	item1.direct_mode = 1;
	item1.connId = 2;
    simcard.push_back(item1);
    /*
     * MQTT
     */
	mqtt.useTls = true;
	mqtt.tlsAuthMode = 0;
	mqtt.cmdCallInterval = 15;
#if MODE_CONFIGS_PHI
	mqtt.server.port = 1883;
	mqtt.server.address = "54.191.223.33";
	mqtt.cliendId = "TesteGW";
	mqtt.pubTopic = "dataFlavio";
	mqtt.cmdTopic = "cmds";
	mqtt.rspTopic = "rsps";
	mqtt.lwTopic = "online";
	mqtt.username = "phi";
	mqtt.password = "phi";
#elif MODE_CONFIGS_KARCHER
	mqtt.server.port = 1883;
	strcpy(mqtt.server.address,"192.168.0.10");
	strcpy(mqtt.cliendId,"Inj");
	strcpy(mqtt.pubTopic,"data");
	strcpy(mqtt.cmdTopic,"cmds");
	strcpy(mqtt.rspTopic,"rsps");
	strcpy(mqtt.lwTopic,"online");
	strcpy(mqtt.username,"phi");
	strcpy(mqtt.password,"phi");
#else
	mqtt.server.port = 1883;
	strcpy(mqtt.server.address,"mqtt.tago.io");
	strcpy(mqtt.cliendId,"ks3000");
	strcpy(mqtt.pubTopic,"tago/data/post");
	strncpy(mqtt.cmdTopic,"cmds",4);
	strncpy(mqtt.rspTopic,"rsps",4);
	strncpy(mqtt.username,"gw",3);
	strncpy(mqtt.password,"phi",3);
#endif

#if MODE_CONFIGS_KARCHER
	inputEnabled = 1;
	input1PulseCounterEnable = 1;
	input1PulseCounterStart = PULSE_COUNTER_START_RISING;
	input1SendPulseEvent = 1;
#elif MODE_CONFIGS_PHI
	inputEnabled = 1;
	input1PulseCounterEnable = 1;
	input1PulseCounterStart = PULSE_COUNTER_START_RISING;
	input1SendPulseEvent = 1;
#else
	inputEnabled = 0;
	input1PulseCounterEnable = 0;
	input1PulseCounterStart = PULSE_COUNTER_START_RISING;
	input1SendPulseEvent = 0;
#endif
}

int Configuration::load(void) {
    /*
     * Open the configuration file
     */
    FILE *fp;
    fp = fopen(CONFIG_FILE,"r");
    if (fp == NULL) {
        syslog(LOG_ERR, "Unable to open configuration file: %s\n", CONFIG_FILE);
        return -1;
    }

    /*
     * Get the file size
     */
    fseek(fp, 0, SEEK_END);
    int len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /*
     * Allocate memory for reading data
     */
    char *data = (char*)malloc(len + 1);
    if (data == NULL) {
        syslog(LOG_ERR, "Problem initializing memory for reading configuration file: %s\n", CONFIG_FILE);
        fclose(fp);
        return -1;
    }
    memset(data,0,len+1);

    /*
     * Read file content
     */
    int nread = fread(data,1,len,fp);
    if (nread != len) {
        syslog(LOG_ERR, "Problem reading configuration file: %s\n", CONFIG_FILE);
        free(data);
        fclose(fp);
        return -1;
    }

    /*
     * Extract content
     */
    int ret = ConfigData::extractConfigFileContent(data, this);

    /*
     * Ending
     */
    free(data);
    fclose(fp);

    return ret;
}

int Configuration::save(void) {
	int ret = 0;
    std::string output = ConfigData::buildConfigFileContent(this);
    
    /*
     * Save output to file
     */
    FILE *fp = NULL;
    fp = fopen(CONFIG_FILE,"w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Problem opening configuration file for writing: %s\n", CONFIG_FILE);
        return -1;
    }
    
    size_t nwrite = fwrite(output.c_str(),1,output.size(),fp);
    if (nwrite < 0) {
        syslog(LOG_ERR, "Problem writing configuration file\n");
		ret = -1;
    }
    else if (nwrite != output.size()) {
        syslog(LOG_WARNING, "Configuration file not written completely\n");
    }

    fclose(fp);

    syslog(LOG_INFO, "Configuration saved in disk\n");
    return ret;
}

int Configuration::createCertificate(void) {
	int ret = 0;
    
    /*
     * Save output to file
     */
    FILE *fp = NULL;
    fp = fopen(CERTIFICATE_FILE,"w");
    if (fp == NULL) {
        syslog(LOG_ERR, "Problem opening certificate file for writing: %s\n", CERTIFICATE_FILE);
        return -1;
    }
    
	size_t certLen = strlen(BASE_CERTIFICATE);
    size_t nwrite = fwrite(BASE_CERTIFICATE,1,certLen,fp);
    if (nwrite < 0) {
        syslog(LOG_ERR, "Problem writing certificate file\n");
		ret = -1;
    }
    else if (nwrite != certLen) {
        syslog(LOG_WARNING, "Certificate file not written completely\n");
    }

    fclose(fp);

    syslog(LOG_INFO, "Certificate saved in disk\n");
    return ret;
}
