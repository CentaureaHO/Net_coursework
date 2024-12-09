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
    LOG(packet_logger, "Sent ARP request for IP: ", ip);

    ARPFrame* data = nullptr;
    // chrono::steady_clock::time_point start = chrono::steady_clock::now();
    // chrono::steady_clock::time_point now   = start;
    while ((res = pcap_next_ex(handle, &buffer_header, &buffer_data)) >= 0)
    {
        // 超时处理（已注释）
        /*
        if (now - start > chrono::seconds(5))
        {
            LOG_ERR(glb_logger, "Failed to get mac for ", ip, ": ", pcap_geterr(handle));
            return false;
        }
        now = chrono::steady_clock::now();
        */

        if (res == 0) continue;

        data = (ARPFrame*)buffer_data;
        if (iptos(data->send_ip) != ip) continue;        // 不是目标IP
        if (data->operation != htons(0x0002)) continue;  // 不是ARP回复
        for (size_t i = 0; i < 6; ++i) mac[i] = data->eth_header.src_mac[i];
        LOG(packet_logger,
            "Received ARP reply for IP: ",
            ip,
            " MAC: ",
            hex,
            (int)mac[0],
            "-",
            (int)mac[1],
            "-",
            (int)mac[2],
            "-",
            (int)mac[3],
            "-",
            (int)mac[4],
            "-",
            (int)mac[5]);
        break;
    }

    if (res < 0)
    {
        LOG_ERR(glb_logger, "pcap_next_ex error: ", pcap_geterr(handle));
        return false;
    }

    arp_table->insert(ip, mac);
    LOG(packet_logger,
        "Inserted ARP entry: ",
        ip,
        " -> ",
        hex,
        setw(2),
        setfill('0'),
        (int)mac[0],
        "-",
        (int)mac[1],
        "-",
        (int)mac[2],
        "-",
        (int)mac[3],
        "-",
        (int)mac[4],
        "-",
        (int)mac[5]);
    return true;
}

void print_mac_table()
{
    LOG(glb_logger, "Printing ARP table.");
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
    LOG(glb_logger, "ARP table printed successfully.");
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
    for (int mi_bit = 31; mi_bit >= 0; --mi_bit)
    {
        if (mask_int & (1 << mi_bit))
            ++cnt;
        else
            break;
    }
    LOG(glb_logger, "Converted netmask ", str_mask, " to CIDR: ", (int)cnt);
    return cnt;
}

bool send_icmp_error(const IPFrame& original_ip_frame, uint8_t type, uint8_t code)
{
    size_t original_ip_header_len = (original_ip_frame.ip_header.ver_hlen & 0x0F) * 4;
    size_t icmp_data_len          = original_ip_header_len + 8;
    size_t icmp_total_len = sizeof(uint8_t) * 2 + sizeof(uint16_t) + icmp_data_len;  // type, code, checksum, data
    size_t total_size     = sizeof(EthHeader) + sizeof(IPHeader) + icmp_total_len;

    uint8_t* buffer = new uint8_t[total_size];
    memset(buffer, 0, total_size);

    EthHeader* eth_header = (EthHeader*)buffer;
    IPHeader*  ip_header  = (IPHeader*)(buffer + sizeof(EthHeader));
    uint8_t*   icmp_ptr   = buffer + sizeof(EthHeader) + sizeof(IPHeader);

    memcpy(eth_header->des_mac, original_ip_frame.eth_header.src_mac, 6);
    memcpy(eth_header->src_mac, local_mac, 6);
    eth_header->frame_type = htons(0x0800);

    ip_header->ver_hlen     = (4 << 4) | 5;
    ip_header->tos          = 0;
    ip_header->total_len    = htons(sizeof(IPHeader) + icmp_total_len);
    ip_header->id           = htons(0);
    ip_header->flag_segment = htons(0);
    ip_header->ttl          = 64;
    ip_header->protocol     = 1;
    ip_header->checksum     = 0;
    ip_header->src_ip       = original_ip_frame.ip_header.dst_ip;
    ip_header->dst_ip       = original_ip_frame.ip_header.src_ip;

    ip_header->checksum = genCheckSum(*ip_header);

    icmp_ptr[0]            = type;
    icmp_ptr[1]            = code;
    uint16_t* checksum_ptr = (uint16_t*)(icmp_ptr + 2);
    *checksum_ptr          = 0;

    memcpy(icmp_ptr + 4, &original_ip_frame.ip_header, original_ip_header_len);
    memcpy(icmp_ptr + 4 + original_ip_header_len, buffer_data + sizeof(IPFrame), 8);

    uint16_t icmp_checksum = compute_checksum((uint16_t*)icmp_ptr, icmp_total_len);
    *checksum_ptr          = icmp_checksum;

    if (pcap_sendpacket(handle, buffer, total_size) == 0)
    {
        LOG(packet_logger,
            "Sent ICMP error message type ",
            (int)type,
            " code ",
            (int)code,
            " to ",
            iptos(ip_header->dst_ip));
        delete[] buffer;
        return true;
    }
    else
    {
        LOG_ERR(glb_logger, "Failed to send ICMP error message: ", pcap_geterr(handle));
        delete[] buffer;
        return false;
    }
}

void packet_handler()
{
    EthHeader* eth_header = (EthHeader*)buffer_data;

    // 仅处理发送给本设备的包
    if (memcmp(eth_header->des_mac, local_mac, 6) != 0) return;

    if (ntohs(eth_header->frame_type) == 0x0806)
    {
        // 处理 ARP 数据包
        ARPFrame* arp_frame = (ARPFrame*)buffer_data;
        if (arp_frame->operation == htons(0x0001))
        {
            // ARP 请求
            LOG(packet_logger, "Received ARP request from IP: ", iptos(arp_frame->send_ip));

            ARPFrame reply_frame;
            MAKE_ARP(reply_frame);
            for (size_t i = 0; i < 6; ++i)
            {
                reply_frame.eth_header.des_mac[i] = arp_frame->send_ha[i];
                reply_frame.eth_header.src_mac[i] = local_mac[i];
                reply_frame.send_ha[i]            = local_mac[i];
                reply_frame.recv_ha[i]            = arp_frame->send_ha[i];
            }
            reply_frame.send_ip = inet_addr(local_ip.c_str());
            reply_frame.recv_ip = arp_frame->send_ip;

            if (pcap_sendpacket(handle, (u_char*)&reply_frame, sizeof(ARPFrame)) == 0)
            {
                LOG(packet_logger, "Sent ARP reply to IP: ", iptos(arp_frame->send_ip));
            }
            else { LOG_ERR(glb_logger, "Failed to send ARP reply: ", pcap_geterr(handle)); }
        }
        else if (arp_frame->operation == htons(0x0002))
        {
            // ARP 回复
            LOG(packet_logger,
                "Captured ARP reply: IP ",
                iptos(arp_frame->send_ip),
                " -> ",
                hex,
                setw(2),
                setfill('0'),
                (int)arp_frame->send_ha[0],
                "-",
                setw(2),
                setfill('0'),
                (int)arp_frame->send_ha[1],
                "-",
                setw(2),
                setfill('0'),
                (int)arp_frame->send_ha[2],
                "-",
                setw(2),
                setfill('0'),
                (int)arp_frame->send_ha[3],
                "-",
                setw(2),
                setfill('0'),
                (int)arp_frame->send_ha[4],
                "-",
                setw(2),
                setfill('0'),
                (int)arp_frame->send_ha[5],
                "; adding to ARP table.");
            arp_table->insert(iptos(arp_frame->send_ip), arp_frame->send_ha);
        }
        return;
    }

    if (ntohs(eth_header->frame_type) != 0x0800) return;  // 仅处理 ARP 或 IPv4 数据包

    // 处理 IP 数据包
    IPFrame* ip_frame = (IPFrame*)buffer_data;

    if (!checkCheckSum(*ip_frame))
    {
        LOG_WARN(glb_logger, "Invalid checksum for IP packet from ", iptos(ip_frame->ip_header.src_ip));
        return;
    }

    if (ip_frame->ip_header.ttl <= 1)
    {
        LOG_WARN(glb_logger, "TTL expired for IP packet from ", iptos(ip_frame->ip_header.src_ip));
        // 发送 ICMP Time Exceeded 报文
        send_icmp_error(*ip_frame, 11, 0);
        return;
    }

    bool send_to_here = false;
    for (auto& [local_ip, mask] : local_ips)
    {
        if (ip_frame->ip_header.dst_ip == inet_addr(local_ip.c_str()))
        {
            send_to_here = true;
            break;
        }
    }

    if (send_to_here)
    {
        // LOG(packet_logger, "Packet is destined for this router. No forwarding needed.");
        return;  // 目标为本机，不需要转发
    }
    if (IS_BROADCAST_FRAME(ip_frame->eth_header))
    {
        // LOG(packet_logger, "Packet is a broadcast frame. Ignoring.");
        return;  // 广播帧，忽略
    }

    LOG(packet_logger,
        "Captured IP packet from ",
        iptos(ip_frame->ip_header.src_ip),
        " to ",
        iptos(ip_frame->ip_header.dst_ip));

    string next_jump = route_tree->lookup(iptos(ip_frame->ip_header.dst_ip), 32);
    LOG(packet_logger,
        "Lookup result for destination IP ",
        iptos(ip_frame->ip_header.dst_ip),
        ": Next jump = ",
        next_jump);

    if (next_jump.empty())
    {
        LOG_WARN(glb_logger, "No route found for IP ", iptos(ip_frame->ip_header.dst_ip));
        // 发送 ICMP Destination Unreachable 报文
        send_icmp_error(*ip_frame, 3, 0);  // Type 3, Code 0 (Network Unreachable)
        return;
    }

    if (next_jump == "Direct")
    {
        struct in_addr addr;
        addr.s_addr = ip_frame->ip_header.dst_ip;
        next_jump   = string(inet_ntoa(addr));
        LOG(packet_logger, "Next jump is direct. IP: ", next_jump);
    }

    if (!get_mac(next_jump, mac_buffer))
    {
        LOG_WARN(glb_logger, "Failed to resolve MAC for next hop: ", next_jump);
        return;  // 获取目标MAC失败
    }

    // 修改 IP 包的 TTL
    --ip_frame->ip_header.ttl;
    LOG(packet_logger, "Decremented TTL. New TTL: ", (int)ip_frame->ip_header.ttl);

    // 更新 Ethernet 头部
    for (size_t i = 0; i < 6; ++i)
    {
        ip_frame->eth_header.src_mac[i] = local_mac[i];
        ip_frame->eth_header.des_mac[i] = mac_buffer[i];
    }
    genCheckSum(*ip_frame);
    LOG(packet_logger, "Recomputed checksum for IP packet.");

    size_t data_len = ntohs(ip_frame->ip_header.total_len) + sizeof(EthHeader);
    if (pcap_sendpacket(handle, (u_char*)ip_frame, data_len) == 0)
    {
        LOG(packet_logger, "Forwarded packet to ", next_jump);
        // cout << "Send packet to " << next_jump << '\n';
    }
    else
    {
        LOG_ERR(glb_logger, "Failed to send packet to ", next_jump, ": ", pcap_geterr(handle));
        // cout << "Failed to send packet to " << next_jump << '\n';
    }
}

void capture_packets(pcap_t* handle)
{
    LOG(glb_logger, "Packet capture thread started.");
    while (running)
    {
        if ((res = pcap_next_ex(handle, &buffer_header, &buffer_data)) >= 0)
        {
            if (res == 0) continue;
            packet_handler();
        }
        else
        {
            LOG_ERR(glb_logger, "Failed to capture packets: ", pcap_geterr(handle));
            break;
        }
    }
    LOG(glb_logger, "Packet capture thread terminated.");
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

    LOG(glb_logger, "Selected device: ", (dev->description ? dev->description : "Anonymous device"));

    getLocalIPs(dev, local_ips);
    if (local_ips.empty())
    {
        LOG_ERR(glb_logger, "Failed to get local IPs");
        LOG(glb_logger, "Router End");
        return 2;
    }
    local_ip = local_ips.back().first;
    stringstream log_stream;
    log_stream << "Get local IPs:\n";
    for (size_t i = 0; i < local_ips.size() - 1; ++i)
        log_stream << "\t" << i + 1 << ". IP: " << local_ips[i].first << "/" << (int)local_ips[i].second << '\n';
    log_stream << "\t" << local_ips.size() << ". IP: " << local_ips.back().first << "/" << (int)local_ips.back().second;
    cout << log_stream.str() << endl;
    LOG(glb_logger, log_stream.str());
    log_stream.str("");
    log_stream.clear();

    handle = pcap_open_live(dev->name, 65535, 0, 1000, errbuf);
    if (!handle)
    {
        LOG_ERR(glb_logger, "Failed to open device: ", errbuf);
        LOG(glb_logger, "Router End");
        return 3;
    }
    LOG(glb_logger, "Opened device for packet capture: ", (dev->description ? dev->description : "Anonymous device"));

    struct bpf_program fp;
    const char*        filter_exp = "arp or ip";
    bpf_u_int32        net        = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        LOG_ERR(glb_logger, "Failed to compile filter: ", pcap_geterr(handle));
        return 4;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        LOG_ERR(glb_logger, "Failed to set filter: ", pcap_geterr(handle));
        pcap_freecode(&fp);
        return 5;
    }

    pcap_freecode(&fp);
    LOG(glb_logger, "Applied BPF filter: ", filter_exp);

    // 发送初始 ARP 请求以获取本地 MAC 地址
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

    if (pcap_sendpacket(handle, (u_char*)&arp_frame, sizeof(ARPFrame)) == 0)
    {
        LOG(packet_logger, "Sent initial ARP request to 114.51.41.91");
    }
    else { LOG_ERR(glb_logger, "Failed to send initial ARP request: ", pcap_geterr(handle)); }

    ARPFrame* data = nullptr;
    while (true)
    {
        res = pcap_next_ex(handle, &buffer_header, &buffer_data);

        if (res == 0) continue;

        data = (ARPFrame*)buffer_data;
        if (data->operation != htons(0x0002)) continue;  // Handle reply packet only
        if (iptos(data->send_ip) != local_ip) continue;

        for (size_t i = 0; i < 6; ++i) local_mac[i] = data->send_ha[i];

        printf("Get local mac: %02X-%02X-%02X-%02X-%02X-%02X\n",
            local_mac[0],
            local_mac[1],
            local_mac[2],
            local_mac[3],
            local_mac[4],
            local_mac[5]);
        LOG(glb_logger,
            "Obtained local MAC address: ",
            hex,
            setw(2),
            setfill('0'),
            (int)local_mac[0],
            "-",
            (int)local_mac[1],
            "-",
            (int)local_mac[2],
            "-",
            (int)local_mac[3],
            "-",
            (int)local_mac[4],
            "-",
            (int)local_mac[5]);
        break;
    }
    if (res <= 0)
    {
        LOG_ERR(glb_logger, "Failed to get local MAC: ", pcap_geterr(handle));
        LOG(glb_logger, "Router End");
        return 6;
    }

    // 初始化路由表与 ARP 表
    route_tree = new RouteTree(dev);
    arp_table  = new ARP_Table();
    arp_table->set_timeout(30);
    LOG(glb_logger, "Initialized routing table and ARP table.");

#ifndef DBG_ARP
    thread packet_thread(capture_packets, handle);
    LOG(glb_logger, "Started packet capture thread.");
#endif

    int     choice = 0;
    string  ip, mask, next_jump;
    uint8_t mask_num = 0, res_code = 0;
#ifdef DBG_ARP
    uint8_t mac[6];
#endif
    while (true)
    {
        cout << "Options: \n"
             << "\t0. Close router\n"
             << "\t1. Add route\n"
             << "\t2. Delete route\n"
             << "\t3. Print route table\n"
             << "\t4. Print ARP table\n"
#ifdef DBG_ARP
             << "\t5. Request ARP\n"
#endif
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
                    LOG_WARN(glb_logger, "User entered invalid netmask: ", mask);
                    break;
                }

                res_code = route_tree->add_route(ip, mask_num, next_jump);
                if (res_code == 0)
                {
                    cout << "Add route successfully\n";
                    LOG(glb_logger, "Added route: ", ip, "/", (int)mask_num, " via ", next_jump);
                }
                else if (res_code == 1)
                {
                    cout << "Modify route successfully\n";
                    LOG(glb_logger, "Modified route: ", ip, "/", (int)mask_num, " via ", next_jump);
                }
                else
                {
                    cout << "Cannot modify direct route\n";
                    LOG_WARN(glb_logger, "Attempted to modify direct route: ", ip, "/", (int)mask_num);
                }

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
                    LOG_WARN(glb_logger, "User entered invalid netmask: ", mask);
                    break;
                }

                res_code = route_tree->remove_route(ip, mask_num);
                if (res_code == 0)
                {
                    cout << "Remove route successfully\n";
                    LOG(glb_logger, "Removed route: ", ip, "/", (int)mask_num);
                }
                else if (res_code == 1)
                {
                    cout << "Remove route failed\n";
                    LOG_WARN(glb_logger, "Failed to remove route: ", ip, "/", (int)mask_num);
                }
                else
                {
                    cout << "Cannot remove direct route\n";
                    LOG_WARN(glb_logger, "Attempted to remove direct route: ", ip, "/", (int)mask_num);
                }

                break;
            }
            case 3:
                cout << '\n';
                route_tree->print();
                cout << '\n';
                LOG(glb_logger, "Printed routing table.");
                break;
            case 4:
                cout << '\n';
                print_mac_table();
                cout << '\n';
                break;
#ifdef DBG_ARP
            case 5:
            {
                cout << "Enter ip: ";
                cin >> ip;
                if (get_mac(ip, mac))
                {
                    cout << "MAC: ";
                    printf("%02X-%02X-%02X-%02X-%02X-%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    LOG(packet_logger,
                        "Requested MAC for IP ",
                        ip,
                        " is ",
                        hex,
                        (int)mac[0],
                        "-",
                        setw(2),
                        setfill('0'),
                        (int)mac[1],
                        "-",
                        setw(2),
                        setfill('0'),
                        (int)mac[2],
                        "-",
                        setw(2),
                        setfill('0'),
                        (int)mac[3],
                        "-",
                        setw(2),
                        setfill('0'),
                        (int)mac[4],
                        "-",
                        setw(2),
                        setfill('0'),
                        (int)mac[5]);
                }
                else
                {
                    cout << "Failed to get mac\n";
                    LOG_WARN(glb_logger, "Failed to get MAC for IP: ", ip);
                }
                break;
            }
#endif
            default:
                cout << "Invalid choice\n";
                LOG_WARN(glb_logger, "User entered invalid choice: ", choice);
                break;
        }
    }

    // 资源由 MemControl 管理，不需要在此处释放
    running = false;
#ifndef DBG_ARP
    packet_thread.join();
    LOG(glb_logger, "Packet capture thread joined.");
#endif
    LOG(glb_logger, "Router End");
    return 0;
}