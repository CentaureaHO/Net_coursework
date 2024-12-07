#include <net/socket_defs.h>
#include <common/log.h>
#include <iostream>
using namespace std;

class SocketInitializer
{
  private:
    SocketInitializer();
    ~SocketInitializer();

  public:
    static SocketInitializer& getInstance();
};

SocketInitializer::SocketInitializer()
{
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        LOG_ERR(glb_logger, "WSAStartup failed, error code: ", WSAGetLastError());
        exit(1);
    }
#endif
}

SocketInitializer::~SocketInitializer() { SOCKCLEANUP(); }

SocketInitializer& SocketInitializer::getInstance()
{
    static SocketInitializer instance;
    return instance;
}

namespace
{
    SocketInitializer& socket_initializer = SocketInitializer::getInstance();
}