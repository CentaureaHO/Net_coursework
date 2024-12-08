#include <net/package.h>
#include <net/socket_defs.h>
using namespace std;

#ifndef IPTOSBUFFERS
#define IPTOSBUFFERS    12
#endif

char* iptos(uint64_t in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static int16_t which = 0;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);

    uint8_t* p = (uint8_t*)&in;
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}