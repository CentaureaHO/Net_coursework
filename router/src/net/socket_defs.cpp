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

#ifdef _WIN32
string extract_guid(const string& dev_name)
{
    size_t start = dev_name.find('{');
    size_t end   = dev_name.find('}', start);
    if (start != string::npos && end != string::npos) { return dev_name.substr(start, end - start + 1); }
    return "";
}
#endif