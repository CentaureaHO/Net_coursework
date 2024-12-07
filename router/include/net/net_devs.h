#ifndef __NET_NET_DEVS__
#define __NET_NET_DEVS__

#include "socket_defs.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <utility>
#include <stdint.h>

pcap_if_t* getDevice(std::string dev_name);
pcap_if_t* getDevice();

void getLocalIPs(pcap_if_t* dev, std::vector<std::pair<std::string, uint8_t>>& ips);

#endif