#ifndef __COMMON_NET_SOCKET_DEFS_H__
#define __COMMON_NET_SOCKET_DEFS_H__

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
#define CLOSE_SOCKET(s) closesocket(s)
#define SOCKCLEANUP() WSACleanup()
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define SOCKET int
#define CLOSE_SOCKET(s) close(s)
#define SOCKCLEANUP()
#endif

#endif