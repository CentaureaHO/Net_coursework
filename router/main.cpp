#include <net/net_devs.h>
#include <struct/route_tree.h>
#include <common/log.h>
#include <struct/arp_table.h>
#include <bits/stdc++.h>
using namespace std;

namespace
{
    ARP_Table*                    arp_table  = nullptr;
    RouteTree*                    route_tree = nullptr;
    vector<pair<string, uint8_t>> local_ips;

    pcap_if_t*     dev           = nullptr;
    pcap_t*        handle        = nullptr;
    pcap_pkthdr*   buffer_header = nullptr;
    const uint8_t* buffer_data   = nullptr;
    int            res           = 0;

    string       local_ip;
    uint8_t      local_mac[6];
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
            if (arp_table)
            {
                delete arp_table;
                arp_table = nullptr;
            }
            if (route_tree)
            {
                delete route_tree;
                route_tree = nullptr;
            }
            if (handle)
            {
                pcap_close(handle);
                handle = nullptr;
            }

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
            LOG_ERR(glb_logger, "pcap_dispatch failed: ", pcap_geterr(handle));
            break;
        }
        else if (ret == 0)
            continue;
    }
}

bool get_mac(const string& ip, uint8_t* mac)
{
    for (auto& [local_ip, mask] : local_ips)
        if (ip == local_ip)
        {
            for (size_t i = 0; i < 6; ++i) mac[i] = local_mac[i];
            return true;
        }

    if (arp_table->lookup(ip, mac)) return true;

    ARPFrame arp_frame;
    MAKE_ARP(arp_frame);
    for (size_t i = 0; i < 6; ++i)
    {
        arp_frame.eth_header.des_mac[i] = 0xff;
        arp_frame.eth_header.src_mac[i] = local_mac[i];
        arp_frame.send_ha[i]            = local_mac[i];
        arp_frame.recv_ha[i]            = 0x00;
    }
    arp_frame.send_ip = inet_addr(local_ip.c_str());
    arp_frame.recv_ip = inet_addr(ip.c_str());

    pcap_sendpacket(handle, (u_char*)&arp_frame, sizeof(ARPFrame));

    ARPFrame*                        data  = nullptr;
    chrono::steady_clock::time_point start = chrono::steady_clock::now();
    chrono::steady_clock::time_point now   = start;
    while ((res = pcap_next_ex(handle, &buffer_header, &buffer_data)) >= 0)
    {
        if (now - start > chrono::seconds(5))
        {
            LOG_ERR(glb_logger, "Failed to get mac for ", ip, ": ", pcap_geterr(handle));
            return false;
        }
        now = chrono::steady_clock::now();

        if (res == 0) continue;

        data = (ARPFrame*)buffer_data;
        if (iptos(data->send_ip) != ip) continue;
        for (size_t i = 0; i < 6; ++i) mac[i] = data->eth_header.src_mac[i];
        break;
    }

    arp_table->insert(ip, mac);
    return true;
}

void print_mac_table()
{
    cout << "ARP table: \n";
    for (auto& [ip, mask] : local_ips)
    {
        printf("\t(local) %s -> %02X-%02X-%02X-%02X-%02X-%02X\n",
            ip.c_str(),
            local_mac[0],
            local_mac[1],
            local_mac[2],
            local_mac[3],
            local_mac[4],
            local_mac[5]);
    }
    arp_table->print();
}

uint8_t strMask2num(const string& str_mask)
{
    uint8_t hi, mi, lo, la;
    if (sscanf(str_mask.c_str(), "%hhu.%hhu.%hhu.%hhu", &hi, &mi, &lo, &la) != 4)
    {
        LOG_ERR(glb_logger, "Error parsing netmask: ", str_mask);
        return 255;
    }

    uint32_t mask_int = (hi << 24) | (mi << 16) | (lo << 8) | la;
    uint8_t  cnt      = 0;
    for (int mi = 31; mi >= 0; --mi)
    {
        if (mask_int & (1 << mi))
            ++cnt;
        else
            break;
    }
    return cnt;
}

int main()
{
    LOG(glb_logger, "Router Start");

    dev = getDevice();
    if (!dev)
    {
        LOG_ERR(glb_logger, "Failed to get device");
        LOG(glb_logger, "Router End");
        return 1;
    }

    getLocalIPs(dev, local_ips);
    if (local_ips.empty())
    {
        LOG_ERR(glb_logger, "Failed to get local ips");
        LOG(glb_logger, "Router End");
        return 2;
    }
    local_ip = local_ips[0].first;
    stringstream log_stream;
    log_stream << "Get local ips: \n";
    for (size_t i = 0; i < local_ips.size() - 1; ++i)
        log_stream << "\t" << i + 1 << ". IP: " << local_ips[i].first << "/" << (int)local_ips[i].second << '\n';
    log_stream << "\t" << local_ips.size() << ". IP: " << local_ips.back().first << "/" << (int)local_ips.back().second;
    cout << log_stream.str() << endl;
    LOG(glb_logger, log_stream.str());
    log_stream.str("");
    log_stream.clear();

    handle = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);
    if (!handle)
    {
        LOG_ERR(glb_logger, "Faile to open device: ", errbuf);
        LOG(glb_logger, "Router End");
        return 3;
    }

    // 获取本地mac
    ARPFrame arp_frame;
    MAKE_ARP(arp_frame);
    for (size_t i = 0; i < 6; ++i)
    {
        arp_frame.eth_header.des_mac[i] = 0xff;
        arp_frame.eth_header.src_mac[i] = 0x11;
        arp_frame.send_ha[i]            = 0x11;
        arp_frame.recv_ha[i]            = 0x00;
    }
    arp_frame.send_ip = inet_addr("114.51.41.91");
    arp_frame.recv_ip = inet_addr(local_ip.c_str());

    pcap_sendpacket(handle, (u_char*)&arp_frame, sizeof(ARPFrame));

    IPFrame*                         data    = nullptr;
    bool                             success = false;
    chrono::steady_clock::time_point start   = chrono::steady_clock::now();
    chrono::steady_clock::time_point now     = start;
    while ((res = pcap_next_ex(handle, &buffer_header, &buffer_data)) >= 0)
    {
        if (now - start > chrono::seconds(5)) break;
        now = chrono::steady_clock::now();

        if (res == 0) continue;

        data = (IPFrame*)buffer_data;
        if (iptos(data->ip_header.src_ip) != local_ip) continue;
        success = true;

        for (size_t i = 0; i < 6; ++i) local_mac[i] = data->eth_header.src_mac[i];

        printf("Get local mac: %02X-%02X-%02X-%02X-%02X-%02X\n",
            local_mac[0],
            local_mac[1],
            local_mac[2],
            local_mac[3],
            local_mac[4],
            local_mac[5]);
        break;
    }
    if (!success)
    {
        LOG_ERR(glb_logger, "Failed to get local mac: ", pcap_geterr(handle));
        LOG(glb_logger, "Router End");
        return 4;
    }

    // 初始化路由表与ARP表
    route_tree = new RouteTree(dev);
    arp_table  = new ARP_Table();

    int     choice = 0;
    string  ip, mask, next_jump;
    uint8_t mask_num = 0, res = 0;
    while (true)
    {
        cout << "Options: \n"
             << "\t0. Close router\n"
             << "\t1. Add route\n"
             << "\t2. Delete route\n"
             << "\t3. Print route table\n"
             << "\t4. Print ARP table\n"
             << "Enter choice: ";
        cin >> choice;
        if (choice == 0) break;
        switch (choice)
        {
            case 1:
            {
                cout << "Enter 'ip mask next_jump': ";
                cin >> ip >> mask >> next_jump;
                mask_num = strMask2num(mask);
                if (mask_num > 32)
                {
                    cout << "Invalid mask\n";
                    break;
                }

                res = route_tree->add_route(ip, mask_num, next_jump);
                if (res == 0)
                    cout << "Add route successfully\n";
                else if (res == 1)
                    cout << "Modify route successfully\n";
                else
                    cout << "Cannot modify direct route\n";

                break;
            }
            case 2:
            {
                cout << "Enter 'ip mask': ";
                cin >> ip >> mask;
                mask_num = strMask2num(mask);
                if (mask_num > 32)
                {
                    cout << "Invalid mask\n";
                    break;
                }

                res = route_tree->remove_route(ip, mask_num);
                if (res == 0)
                    cout << "Remove route successfully\n";
                else if (res == 1)
                    cout << "Remove route failed\n";
                else
                    cout << "Cannot remove direct route\n";

                break;
            }
            case 3:
                cout << '\n';
                route_tree->print();
                cout << '\n';
                break;
            case 4:
                cout << '\n';
                print_mac_table();
                cout << '\n';
                break;
            default: cout << "Invalid choice\n"; break;
        }
    }

    /*
        string  remote_ip = "";
        uint8_t remote_mac[6];
        while (true)
        {
            cout << "请输入目标IP地址(q to quit): ";
            cin >> remote_ip;
            if (remote_ip == "q") break;

            get_mac(remote_ip, remote_mac);
            print_mac_table();
        }

        thread capture_thread(capture_packets, handle);

        cout << "开始捕获数据包。按回车键停止。" << endl;
        cin.ignore();
        cin.get();
        running = false;
    */

    // 清理资源
    // capture_thread.join();
    LOG(glb_logger, "Router End");
    return 0;
}