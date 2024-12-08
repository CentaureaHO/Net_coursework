#include <net/net_devs.h>
#include <struct/route_tree.h>
#include <common/log.h>
#include <bits/stdc++.h>
using namespace std;

namespace
{
    char*        errbuf;
    atomic<bool> running(true);

    Logger packet_logger("Router_packet.log");

    // singleton
    class MemControl
    {
      private:
        MemControl() { errbuf = new char[PCAP_ERRBUF_SIZE]; }
        ~MemControl() { delete[] errbuf; }

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

    pcap_t* handle = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);
    if (!handle)
    {
        LOG_ERR(glb_logger, "Open device failed: ", errbuf);
        LOG(glb_logger, "Router End");
        return 2;
    }

    thread capture_thread(capture_packets, handle);

    cout << "开始捕获数据包。按回车键停止。" << endl;
    cin.ignore();
    cin.get();
    running = false;

    // 清理资源
    capture_thread.join();
    pcap_close(handle);
    LOG(glb_logger, "Router End");
    return 0;
}