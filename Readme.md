# IOT Gateway firmware

This project implements an Iot gateway firmware to run on PHI Innovations's [IoT gateway](https://github.com/phi-innovations/iot-gateway-hw) hardware.

This is a PHI Gateway firmware done in C++ running on Nuttx.

These are the main aspects of this project.

* Use Nuttx as a library (nuttx-export-10.0.1)
* Use Cmake as build engine
* Has automation to load firmware on the board using Segger J-Link

The purpose of this project is to use C++ on a larger embedded firmware project and deployed in a way where it could be easily integraded by development software teams.

The use of NuttX as a library allows this, with the side-effect to let the on-the-fly NuttX customization harder.

# Subcomponents

This project uses the following subcomponents:

* libmodbus
* mbedtls
* mqtt-c

These open souce projects were forked and placed on PHI-Innovations github repository.

# Features

* MODBUS Scanning 
  - Periodic scan
  - Individual MODBUS map for each slave
  - Registers saved internally as files, in an independent fashion
* MQTT data transmission
  - Periodic transmission
  - Transmit files previously stored
* USB configuration
  - CDC based USB communication
  - JSON-based messages
* Network management
  - Access to server done by Ethernet
  - WiFi and 2G modem not validated

# Build instruction

```
$ make default
```

# Load the firmware

```
$ make run
```

# TODO

- [ ] Improve documentation
- [ ] Add support for standard bootloader (need to choose one)

