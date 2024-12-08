#include <net/net_devs.h>
#include <struct/route_tree.h>
#include <bits/stdc++.h>
using namespace std;

int main()
{
    pcap_if_t* dev = getDevice();
    RouteTree rt(dev);

    rt.set_default_route("1.1.1.1");

    rt.add_route("192.168.2.0", 24, "2.2.2.2");
    rt.add_route("10.0.0.0", 8, "3.3.3.3");
    rt.add_route("192.168.0.0", 16, "4.4.4.4");

    cout << "=== 路由表初始状态 ===" << endl;
    rt.print();

    vector<pair<string, uint8_t>> test_ips = {
        {"192.168.2.100", 32},
        {"192.168.1.50", 32},
        {"10.1.2.3", 32},
        {"8.8.8.8", 32},
        {"192.168.2.255", 24},
    };

    cout << "\n=== 查找路由 ===" << endl;
    for (const auto& [ip, mask] : test_ips)
    {
        string next_jump = rt.lookup(ip, mask);
        cout << "IP 地址 " << ip << " 匹配的下一跳: " << (next_jump.empty() ? "未找到路由" : next_jump) << endl;
    }

    cout << "\n=== 删除路由 192.168.2.0/24 ===" << endl;
    uint8_t remove_result = rt.remove_route("192.168.2.0", 24);
    if (remove_result == 0)
        cout << "成功删除路由 192.168.2.0/24" << endl;
    else if (remove_result == 1)
        cout << "删除路由 192.168.2.0/24 失败" << endl;
    else
        cout << "不允许删除直连路由 192.168.2.0/24" << endl;

    cout << "\n=== 路由表删除后 ===" << endl;
    rt.print();

    cout << "\n=== 删除路由后的查找 ===" << endl;
    for (const auto& [ip, mask] : test_ips)
    {
        string next_jump = rt.lookup(ip, mask);
        cout << "IP 地址 " << ip << " 匹配的下一跳: " << (next_jump.empty() ? "未找到路由" : next_jump) << endl;
    }

    cout << "\n=== 更新设备后 ===" << endl;
    rt.update_device(dev);
    rt.print();

    rt.add_route("172.16.0.0", 12, "5.5.5.5");

    cout << "\n=== 更新设备后添加新路由 ===" << endl;
    rt.print();

    vector<pair<string, uint8_t>> more_test_ips = {
        {"172.16.5.4", 32},
        {"192.168.1.50", 32},
        {"10.1.2.3", 32},
        {"8.8.8.8", 32},
        {"172.16.255.255", 32},
    };

    cout << "\n=== 更新设备后查找路由 ===" << endl;
    for (const auto& [ip, mask] : more_test_ips)
    {
        string next_jump = rt.lookup(ip, mask);
        cout << "IP 地址 " << ip << " 匹配的下一跳: " << (next_jump.empty() ? "未找到路由" : next_jump) << endl;
    }

    return 0;
}