#ifndef __PACKAGE_H__
#define __PACKAGE_H__

#include <cstdint>

#pragma pack(1)

struct FrameHeader
{
    uint8_t  DesMAC[6];
    uint8_t  SrcMAC[6];
    uint16_t FrameType;
};

struct IPHeader
{
    uint8_t  Ver_HLen;
    uint8_t  TOS;
    uint16_t TotalLen;
    uint16_t ID;
    uint16_t Flag_Segment;
    uint8_t  TTL;
    uint8_t  Protocol;
    uint16_t Checksum;
    uint32_t SrcIP;
    uint32_t DstIP;
};

struct Data
{
    FrameHeader FrameHeader;
    IPHeader    IPHeader;
};

struct ARPFrame
{
    FrameHeader FrameHeader;
    uint16_t    HardwareType;
    uint16_t    ProtocolType;
    uint8_t     HLen;
    uint8_t     PLen;
    uint16_t    Operation;
    uint8_t     SendHa[6];
    uint32_t    SendIP;
    uint8_t     RecvHa[6];
    uint32_t    RecvIP;
};

#pragma pack()

#define MAKE_ARP(arp_frame)                              \
    {                                                    \
        arp_frame.FrameHeader.FrameType = htons(0x0806); \
        arp_frame.HardwareType          = htons(0x0001); \
        arp_frame.ProtocolType          = htons(0x0800); \
        arp_frame.HLen                  = 6;             \
        arp_frame.PLen                  = 4;             \
        arp_frame.Operation             = htons(0x0001); \
    }

#endif