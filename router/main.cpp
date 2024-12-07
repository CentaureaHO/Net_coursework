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

    rt.print();

    rt.update_device(dev);
    rt.print();
}