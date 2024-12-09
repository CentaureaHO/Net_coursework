#include <net/net_devs.h>
#include <struct/route_tree.h>
#include <common/log.h>
#include <struct/arp_table.h>
#include <bits/stdc++.h>
using namespace std;

int main()
{
    RouteTree rt;

    rt.add_route("123.123.123.0", 24, "123");

    cout << rt.lookup()
}