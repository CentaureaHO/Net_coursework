#ifndef __PCAP_DEFS_H__
#define __PCAP_DEFS_H__

#include <pcap.h>

#ifdef _WIN32
#define PCAP_NPCAP

#else
#define PCAP_LIBPCAP
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif