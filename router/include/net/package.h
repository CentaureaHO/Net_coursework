#ifndef __NET_PACKAGE_H__
#define __NET_PACKAGE_H__

#include <pcap.h>
#include <cstdint>

#pragma pack(1)

struct EthHeader
{
    uint8_t  des_mac[6];  // 目标 MAC 地址
    uint8_t  src_mac[6];  // 源 MAC 地址
    uint16_t frame_type;  // 帧类型
};

struct IPHeader
{
    uint8_t  ver_hlen;      // 版本 + 头长度
    uint8_t  tos;           // 服务类型
    uint16_t total_len;     // 总长度
    uint16_t id;            // 标识符
    uint16_t flag_segment;  // 标志 + 片段偏移
    uint8_t  ttl;           // 生存时间
    uint8_t  protocol;      // 协议类型
    uint16_t checksum;      // 校验和
    uint32_t src_ip;        // 源 IP 地址
    uint32_t dst_ip;        // 目标 IP 地址
};

struct IPFrame
{
    EthHeader eth_header;  // 以太网头部
    IPHeader  ip_header;   // IP 头部
};

struct ICMPHeader
{
    uint8_t  type;            // ICMP 类型
    uint8_t  code;            // ICMP 代码
    uint16_t checksum;        // 校验和
    uint16_t identification;  // 标识符
    uint16_t seq;             // 序列号
};

struct ARPFrame
{
    EthHeader eth_header;     // 以太网头部
    uint16_t  hardware_type;  // 硬件类型
    uint16_t  protocol_type;  // 协议类型
    uint8_t   hlen;           // 硬件地址长度
    uint8_t   plen;           // 协议地址长度
    uint16_t  operation;      // 操作类型
    uint8_t   send_ha[6];     // 发送者硬件地址
    uint32_t  send_ip;        // 发送者 IP 地址
    uint8_t   recv_ha[6];     // 接收者硬件地址
    uint32_t  recv_ip;        // 接收者 IP 地址
};

#pragma pack()

#define IS_BROADCAST_FRAME(eth_header)                                                                  \
    (eth_header.des_mac[0] == 0xFF && eth_header.des_mac[1] == 0xFF && eth_header.des_mac[2] == 0xFF && \
        eth_header.des_mac[3] == 0xFF && eth_header.des_mac[4] == 0xFF && eth_header.des_mac[5] == 0xFF)

#define MAKE_ARP(arp_frame)                              \
    {                                                    \
        arp_frame.eth_header.frame_type = htons(0x0806); \
        arp_frame.hardware_type         = htons(0x0001); \
        arp_frame.protocol_type         = htons(0x0800); \
        arp_frame.hlen                  = 6;             \
        arp_frame.plen                  = 4;             \
        arp_frame.operation             = htons(0x0001); \
    }

char*    iptos(uint64_t in);
uint16_t genCheckSum(IPFrame& packet);
bool     checkCheckSum(IPFrame& packet);
uint16_t genCheckSum(ICMPHeader& packet);
bool     checkCheckSum(ICMPHeader& packet);

#endif