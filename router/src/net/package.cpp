#include <net/package.h>
#include <net/socket_defs.h>
using namespace std;

#ifndef IPTOSBUFFERS
#define IPTOSBUFFERS 12
#endif

char* iptos(uint64_t in)
{
    static char    output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static int16_t which = 0;
    which                = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);

    uint8_t* p = (uint8_t*)&in;
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

uint16_t genCheckSum(IPFrame& packet)
{
    packet.ip_header.checksum = 0;
    uint32_t  sum             = 0;
    uint16_t* data            = reinterpret_cast<uint16_t*>(&packet.ip_header);

    for (size_t i = 0; i < sizeof(IPHeader) / 2; ++i)
    {
        sum += data[i];
        if (sum > 0xFFFF) sum -= 0xFFFF;
    }

    packet.ip_header.checksum = ~(sum & 0xFFFF);
    return packet.ip_header.checksum;
}
bool checkCheckSum(IPFrame& packet)
{
    uint32_t  sum  = 0;
    uint16_t* data = reinterpret_cast<uint16_t*>(&packet.ip_header);

    for (size_t i = 0; i < sizeof(IPHeader) / 2; ++i)
    {
        sum += data[i];
        if (sum > 0xFFFF) sum -= 0xFFFF;
    }

    return (sum & 0xFFFF) == 0xFFFF;
}

uint16_t genCheckSum(ICMPHeader& packet)
{
    packet.checksum = 0;
    uint32_t  sum   = 0;
    uint16_t* data  = reinterpret_cast<uint16_t*>(&packet);

    for (size_t i = 0; i < sizeof(ICMPHeader) / 2; ++i)
    {
        sum += data[i];
        if (sum > 0xFFFF) sum -= 0xFFFF;
    }

    packet.checksum = ~(sum & 0xFFFF);
    return packet.checksum;
}
bool checkCheckSum(ICMPHeader& packet)
{
    uint32_t  sum  = 0;
    uint16_t* data = reinterpret_cast<uint16_t*>(&packet);

    for (size_t i = 0; i < sizeof(ICMPHeader) / 2; ++i)
    {
        sum += data[i];
        if (sum > 0xFFFF) sum -= 0xFFFF;
    }

    return (sum & 0xFFFF) == 0xFFFF;
}