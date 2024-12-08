#include <net/net_devs.h>
#include <struct/route_tree.h>
#include <common/log.h>
#include <struct/arp_table.h>
#include <bits/stdc++.h>
using namespace std;

namespace
{
    char*        errbuf     = nullptr;
    uint8_t*     mac_buffer = nullptr;
    atomic<bool> running(true);

    Logger packet_logger("Router_packet.log");

    // singleton
    class MemControl
    {
      private:
        MemControl()
        {
            errbuf     = new char[PCAP_ERRBUF_SIZE];
            mac_buffer = new uint8_t[6];
        }
        ~MemControl()
        {
            delete[] errbuf;
            delete[] mac_buffer;
        }

      public:
        static MemControl& getInstance()
        {
            static MemControl instance;
            return instance;
        }

        MemControl(const MemControl&)            = delete;
        MemControl& operator=(const MemControl&) = delete;
    };

    MemControl& memControl = MemControl::getInstance();
}  // anonymous namespace

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    (void)args;
    (void)packet;
    LOG(packet_logger, "捕获到一个数据包：\n数据包长度: ", header->len, " 字节\n数据内容: passed");
}

void capture_packets(pcap_t* handle)
{
    while (running)
    {
        int ret = pcap_dispatch(handle, 1, packet_handler, nullptr);
        if (ret == -1)
        {
            LOG_ERR(glb_logger, "pcap_dispatch 失败: ", pcap_geterr(handle));
            break;
        }
        else if (ret == 0)
            continue;
    }
}

bool get_mac(const pcap_t* handle, const char* ip, uint8_t* mac)
{
    
}

int main()
{
    LOG(glb_logger, "Router Start");

    pcap_if_t* dev = getDevice();
    if (!dev)
    {
        LOG_ERR(glb_logger, "No device found, exit.");
        LOG(glb_logger, "Router End");
        return 1;
    }

    vector<pair<string, uint8_t>> ips;
    getLocalIPs(dev, ips);
    if (ips.empty())
    {
        LOG_ERR(glb_logger, "No IP address found, exit.");
        LOG(glb_logger, "Router End");
        return 2;
    }

    pcap_t* handle = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);
    if (!handle)
    {
        LOG_ERR(glb_logger, "Open device failed: ", errbuf);
        LOG(glb_logger, "Router End");
        return 3;
    }

    cout << "Using ip: " << ips[0].first << endl;
    ARP_Table arp_table(ips[0].first);

    // 清理资源
    // capture_thread.join();
    pcap_close(handle);
    LOG(glb_logger, "Router End");
    return 0;
}