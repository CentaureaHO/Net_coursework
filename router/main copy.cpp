#include <net/net_devs.h>
#include <struct/route_tree.h>
#include <common/log.h>
#include <struct/arp_table.h>
#include <bits/stdc++.h>
using namespace std;

namespace
{
    unique_ptr<ARP_Table>         arp_table;
    unique_ptr<RouteTree>         route_tree;
    vector<pair<string, uint8_t>> local_ips;

    pcap_if_t*   dev    = nullptr;
    pcap_t*      handle = nullptr;
    char*        errbuf = nullptr;
    uint8_t      local_mac[6];
    string       local_ip;
    atomic<bool> running(true);

    // 线程安全的队列
    deque<vector<u_char>> packet_queue;
    ReWrLock              queue_lock;   // 保护 packet_queue 的读写
    mutex                 cv_mutex;     // 用于 condition_variable
    condition_variable    cv_queue_cv;  // 条件变量，用于通知处理线程

    // 单例内存控制类
    class MemControl
    {
      private:
        MemControl() { errbuf = new char[PCAP_ERRBUF_SIZE]; }
        ~MemControl()
        {
            // 资源由 unique_ptr 自动管理
            delete[] errbuf;
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

// 函数声明
bool    get_mac(const string& ip, uint8_t* mac);
void    print_mac_table();
uint8_t strMask2num(const string& str_mask);
void    handle_arp_request(const ARPFrame* arp_frame);
void    packet_handler(const u_char* packet);
void    packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
void    processing_thread_func();

// 实现函数

/**
 * @brief 获取 MAC 地址
 *
 * 根据 IP 地址获取对应的 MAC 地址。如果在本地 IP 列表中，则返回本机 MAC；否则，通过 ARP 请求获取。
 *
 * @param ip 目标 IP 地址
 * @param mac 输出参数，用于存储获取到的 MAC 地址
 * @return 成功返回 true，失败返回 false
 */
bool get_mac(const string& ip, uint8_t* mac)
{
    // 先尝试从本地 IP 列表中查找
    {
        WriteGuard guard = queue_lock.write();
        for (auto& [local_ip_entry, mask] : local_ips)
        {
            if (ip == local_ip_entry)
            {
                memcpy(mac, local_mac, 6);
                return true;
            }
        }
    }

    // 尝试从 ARP 表中查找
    {
        ReadGuard guard = queue_lock.read();
        if (arp_table->lookup(ip, mac)) return true;
    }

    // 发送 ARP 请求
    ARPFrame arp_frame;
    memset(&arp_frame, 0, sizeof(ARPFrame));

    // 构造 ARP 请求帧
    for (size_t i = 0; i < 6; ++i)
    {
        arp_frame.eth_header.des_mac[i] = 0xff;
        arp_frame.eth_header.src_mac[i] = local_mac[i];
        arp_frame.send_ha[i]            = local_mac[i];
        arp_frame.recv_ha[i]            = 0x00;
    }
    arp_frame.eth_header.frame_type = htons(0x0806);  // ARP
    arp_frame.hardware_type         = htons(1);       // Ethernet
    arp_frame.protocol_type         = htons(0x0800);  // IPv4
    arp_frame.hardware_type         = 6;
    arp_frame.protocol_type         = 4;
    arp_frame.operation             = htons(1);  // ARP request
    arp_frame.send_ip               = inet_addr(local_ip.c_str());
    arp_frame.recv_ip               = inet_addr(ip.c_str());

    // 发送 ARP 请求
    if (pcap_sendpacket(handle, (const u_char*)&arp_frame, sizeof(ARPFrame)) != 0)
    {
        LOG_ERR(glb_logger, "Failed to send ARP request: ", pcap_geterr(handle));
        return false;
    }

    // 等待 ARP 回复
    auto start_time = chrono::steady_clock::now();
    while (chrono::steady_clock::now() - start_time < chrono::seconds(5))
    {
        // 捕获下一个数据包
        struct pcap_pkthdr* header;
        const u_char*       data;
        int                 res = pcap_next_ex(handle, &header, &data);
        if (res == 1)
        {
            EthHeader* eth_header = (EthHeader*)data;
            if (ntohs(eth_header->frame_type) != 0x0806) continue;  // 仅处理 ARP

            ARPFrame* recv_arp = (ARPFrame*)data;
            if (ntohs(recv_arp->operation) != 2) continue;  // 仅处理 ARP 回复

            if (inet_ntoa(*(struct in_addr*)&recv_arp->recv_ip) != ip) continue;  // 仅处理目标 IP 的回复

            memcpy(mac, recv_arp->eth_header.src_mac, 6);

            // 将 ARP 回复插入 ARP 表
            {
                WriteGuard guard = queue_lock.write();
                arp_table->insert(ip, mac);
            }

            return true;
        }
        else if (res == -1 || res == -2)
        {
            LOG_ERR(glb_logger, "Error capturing ARP reply: ", pcap_geterr(handle));
            return false;
        }
        // res == 0 表示超时，继续等待
    }

    LOG_ERR(glb_logger, "Timeout while waiting for ARP reply for IP: ", ip);
    return false;
}

/**
 * @brief 打印 ARP 表
 */
void print_mac_table()
{
    cout << "ARP table:\n";
    // 打印本地 IP 和 MAC
    {
        ReadGuard guard = queue_lock.read();
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

        // 打印 ARP 表
        arp_table->print();
    }
}

/**
 * @brief 将字符串格式的子网掩码转换为数字格式（如 "255.255.255.0" 转换为 24）
 *
 * @param str_mask 子网掩码字符串
 * @return 子网掩码对应的数字，如果解析失败则返回 255
 */
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

/**
 * @brief 处理 ARP 请求
 *
 * @param arp_frame ARP 请求帧
 */
void handle_arp_request(const ARPFrame* arp_frame)
{
    ARPFrame reply_frame;
    memset(&reply_frame, 0, sizeof(ARPFrame));

    // 构造 ARP 回复帧
    for (size_t i = 0; i < 6; ++i)
    {
        reply_frame.eth_header.des_mac[i] = arp_frame->send_ha[i];
        reply_frame.eth_header.src_mac[i] = local_mac[i];
        reply_frame.send_ha[i]            = local_mac[i];
        reply_frame.recv_ha[i]            = arp_frame->send_ha[i];
    }
    reply_frame.eth_header.frame_type = htons(0x0806);  // ARP
    reply_frame.hardware_type         = htons(1);       // Ethernet
    reply_frame.protocol_type         = htons(0x0800);  // IPv4
    reply_frame.hardware_type         = 6;
    reply_frame.protocol_type         = 4;
    reply_frame.operation             = htons(2);  // ARP reply
    reply_frame.send_ip               = inet_addr(local_ip.c_str());
    reply_frame.recv_ip               = arp_frame->send_ip;

    // 发送 ARP 回复
    if (pcap_sendpacket(handle, (const u_char*)&reply_frame, sizeof(ARPFrame)) != 0)
    {
        LOG_ERR(glb_logger, "Failed to send ARP reply: ", pcap_geterr(handle));
    }
}

/**
 * @brief 处理单个数据包
 *
 * @param packet 数据包内容
 */
void packet_handler(const u_char* packet)
{
    EthHeader* eth_header = (EthHeader*)packet;

    // 仅处理发给本设备的包
    if (memcmp(eth_header->des_mac, local_mac, 6) != 0) return;

    uint16_t frame_type = ntohs(eth_header->frame_type);
    if (frame_type == 0x0806)  // ARP
    {
        ARPFrame* arp_frame = (ARPFrame*)packet;
        if (ntohs(arp_frame->operation) == 1)  // ARP request
        {
            handle_arp_request(arp_frame);
        }
        else if (ntohs(arp_frame->operation) == 2)  // ARP reply
        {
            // 插入 ARP 表
            {
                WriteGuard guard = queue_lock.write();
                arp_table->insert(inet_ntoa(*(struct in_addr*)&arp_frame->send_ip), arp_frame->eth_header.src_mac);
            }
        }
    }
    else if (frame_type == 0x0800)  // IPv4
    {
        IPFrame* ip_frame = (IPFrame*)packet;

        if (!checkCheckSum(*ip_frame))
        {
            // 检查和错误，忽略包
            return;
        }
        if (ip_frame->ip_header.ttl <= 1)
        {
            // TTL 超时，发送 ICMP Time Exceeded（待实现）
            return;
        }

        bool send_to_here = false;
        {
            ReadGuard guard = queue_lock.read();
            for (auto& [local_ip_entry, mask] : local_ips)
            {
                if (ip_frame->ip_header.dst_ip == inet_addr(local_ip_entry.c_str()))
                {
                    send_to_here = true;
                    break;
                }
            }
        }

        if (send_to_here) return;  // 包发给本设备，无需转发

        if (memcmp(eth_header->des_mac, "\xff\xff\xff\xff\xff\xff", 6) == 0) return;  // 广播帧，无需转发

        // 查找下一跳
        string next_jump;
        {
            ReadGuard guard = queue_lock.read();
            next_jump       = route_tree->lookup(ip_frame->ip_header.dst_ip, 32);
        }

        if (next_jump.empty()) return;  // 无路由到目标

        if (next_jump == "Direct")
        {
            struct in_addr addr;
            addr.s_addr = ip_frame->ip_header.dst_ip;
            next_jump   = string(inet_ntoa(addr));
        }

        uint8_t dest_mac[6];
        if (!get_mac(next_jump, dest_mac)) return;  // 获取 MAC 失败

        // 修改 IP 头部
        {
            WriteGuard guard = queue_lock.write();
            ip_frame->ip_header.ttl -= 1;
            memcpy(eth_header->src_mac, local_mac, 6);
            memcpy(eth_header->des_mac, dest_mac, 6);
            genCheckSum(*ip_frame);
        }

        size_t data_len = ntohs(ip_frame->ip_header.total_len) + sizeof(EthHeader);
        if (pcap_sendpacket(handle, (const u_char*)ip_frame, data_len) == 0)
        {
            cout << "Sent packet to " << next_jump << '\n';
            // TODO: 日志记录
        }
        else
        {
            cout << "Failed to send packet to " << next_jump << '\n';
            LOG_ERR(glb_logger, "Failed to send packet: ", pcap_geterr(handle));
        }
    }
}

/**
 * @brief pcap 回调函数
 *
 * 将捕获到的数据包复制到队列中，并通知处理线程。
 *
 * @param user 用户数据（未使用）
 * @param header 数据包头信息
 * @param packet 数据包内容
 */
void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    (void)user;
    // 复制数据包内容
    vector<u_char> pkt(packet, packet + header->len);

    // 将数据包加入队列
    {
        WriteGuard guard = queue_lock.write();
        packet_queue.emplace_back(std::move(pkt));
    }

    // 通知处理线程
    cv_queue_cv.notify_one();
}

/**
 * @brief 数据包处理线程函数
 *
 * 从队列中取出数据包并处理。
 */
void processing_thread_func()
{
    while (running)
    {
        unique_lock<mutex> lock(cv_mutex);
        cv_queue_cv.wait(lock, [] { return !packet_queue.empty() || !running; });

        while (true)
        {
            vector<u_char> pkt;
            {
                WriteGuard guard = queue_lock.write();
                if (packet_queue.empty()) break;
                pkt = std::move(packet_queue.front());
                packet_queue.pop_front();
            }

            // 处理数据包
            if (!pkt.empty()) { packet_handler(pkt.data()); }
        }
    }
}

/**
 * @brief 主函数
 */
int main()
{
    LOG(glb_logger, "Router Start");

    // 获取设备
    dev = getDevice();
    if (!dev)
    {
        LOG_ERR(glb_logger, "Failed to get device");
        LOG(glb_logger, "Router End");
        return 1;
    }

    // 获取本地 IP
    getLocalIPs(dev, local_ips);
    if (local_ips.empty())
    {
        LOG_ERR(glb_logger, "Failed to get local IPs");
        LOG(glb_logger, "Router End");
        return 2;
    }

    // 假设最后一个 IP 是主要 IP
    local_ip = local_ips[0].first;

    // 日志记录本地 IP
    stringstream log_stream;
    log_stream << "Get local IPs:\n";
    for (size_t i = 0; i < local_ips.size(); ++i)
    {
        log_stream << "\t" << i + 1 << ". IP: " << local_ips[i].first << "/" << static_cast<int>(local_ips[i].second)
                   << "\n";
    }
    cout << log_stream.str() << endl;
    LOG(glb_logger, log_stream.str());

    // 打开 pcap 设备
    int snaplen    = 65535;  // 捕获的最大字节数
    int promisc    = 0;      // 关闭混杂模式
    int timeout_ms = 1000;   // 超时时间为 1000 毫秒

    handle = pcap_open_live(dev->name, snaplen, promisc, timeout_ms, errbuf);
    if (!handle)
    {
        LOG_ERR(glb_logger, "Failed to open device: ", errbuf);
        LOG(glb_logger, "Router End");
        return 3;
    }

    // 设置 BPF 过滤器，仅捕获 ARP 和 IP 数据包
    struct bpf_program fp;
    const char*        filter_exp = "arp or ip";
    bpf_u_int32        net        = 0;  // 可以根据需要设置网络掩码

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        LOG_ERR(glb_logger, "Failed to compile filter: ", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        LOG_ERR(glb_logger, "Failed to set filter: ", pcap_geterr(handle));
        pcap_freecode(&fp);
        return 1;
    }

    pcap_freecode(&fp);

    // 获取本地 MAC 地址
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

    IPFrame*            data    = nullptr;
    bool                success = false;
    int                 res     = 0;
    struct pcap_pkthdr* header;
    const u_char*       body;
    while ((res = pcap_next_ex(handle, &header, &body)) >= 0)
    {
        if (res == 0) continue;

        data = (IPFrame*)body;
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

    // 初始化路由表与 ARP 表
    route_tree = make_unique<RouteTree>(dev);
    arp_table  = make_unique<ARP_Table>();

    // 启动数据包处理线程
    thread processor_thread(processing_thread_func);

    // 启动 pcap 捕获线程
    thread capture_thread([&]() {
        if (pcap_loop(handle, 0, packet_callback, nullptr) == -1)
        {
            LOG_ERR(glb_logger, "pcap_loop error: ", pcap_geterr(handle));
        }
    });

    // 主循环用户交互
    int     choice = 0;
    string  ip, mask, next_jump;
    uint8_t mask_num = 0, res_code = 0;
#ifdef DBG_ARP
    uint8_t mac_result[6];
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
                    break;
                }

                {
                    WriteGuard guard = queue_lock.write();
                    res_code         = route_tree->add_route(ip, mask_num, next_jump);
                }

                if (res_code == 0)
                    cout << "Add route successfully\n";
                else if (res_code == 1)
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

                {
                    WriteGuard guard = queue_lock.write();
                    res_code         = route_tree->remove_route(ip, mask_num);
                }

                if (res_code == 0)
                    cout << "Remove route successfully\n";
                else if (res_code == 1)
                    cout << "Remove route failed\n";
                else
                    cout << "Cannot remove direct route\n";

                break;
            }
            case 3:
                cout << '\n';
                {
                    ReadGuard guard = queue_lock.read();
                    route_tree->print();
                }
                cout << '\n';
                break;
            case 4:
                cout << '\n';
                print_mac_table();
                cout << '\n';
                break;
#ifdef DBG_ARP
            case 5:
            {
                cout << "Enter IP: ";
                cin >> ip;
                if (get_mac(ip, mac_result))
                {
                    cout << "MAC: ";
                    printf("%02X-%02X-%02X-%02X-%02X-%02X\n",
                        mac_result[0],
                        mac_result[1],
                        mac_result[2],
                        mac_result[3],
                        mac_result[4],
                        mac_result[5]);
                }
                else { cout << "Failed to get MAC\n"; }
                break;
            }
#endif
            default: cout << "Invalid choice\n"; break;
        }
    }

    // 退出时清理资源
    running = false;
    cv_queue_cv.notify_all();
    pcap_breakloop(handle);
    if (capture_thread.joinable()) capture_thread.join();
    if (processor_thread.joinable()) processor_thread.join();

    LOG(glb_logger, "Router End");
    return 0;
}