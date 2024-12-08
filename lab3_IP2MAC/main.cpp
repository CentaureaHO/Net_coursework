#include <iostream>
#include <winsock2.h>
#include <pcap.h>
#include <map>
#include <chrono>
#include <package.h>
using namespace std;

#define IPTOSBUFFERS 12
string                                                      HostIP;
string                                                      HostBroadaddr;
uint8_t                                                     HostMAC[6];
map<string, pair<string, chrono::steady_clock::time_point>> ip_mac_mapping;

char* iptos(u_long in)
{
    static char  output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which = 0;
    which              = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);

    u_char* p = (u_char*)&in;
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

pcap_t* init()
{
    int          i = 0;
    int          num;
    pcap_if_t*   alldevs;
    pcap_if_t*   d;
    pcap_addr_t* a;
    pcap_t*      adhandle;
    char         errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        printf("Error in pcap_findalldevs_ex:%s\n", errbuf);
        return nullptr;
    }

    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. Device: %s\n", ++i, d->name);
        if (d->description) { printf("  Description: (%s)\n", d->description); }
        else { printf("  (No description available)\n\n"); }
    }
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return 0;
    }

    printf("\nEnter the interface number (1-%d):", i);
    scanf("%d", &num);
    if (num < 1 || num > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return 0;
    }

    for (d = alldevs, i = 0; i < num - 1; ++i) d = d->next;

    for (a = d->addresses; a != NULL; a = a->next)
    {
        switch (a->addr->sa_family)
        {
            case AF_INET:
                if (a->addr)
                {
                    printf("Local IPv4 addr: %s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                    HostIP = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
                }
                if (a->broadaddr) HostBroadaddr = iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr);
                break;
        }
    }

    if ((adhandle = pcap_open_live(d->name, 65536, 1, 10, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter.\n");
        pcap_freealldevs(alldevs);
    }

    pcap_freealldevs(alldevs);

    return adhandle;
}

void print_mapping()
{
    auto now = chrono::steady_clock::now();
    for (auto it = ip_mac_mapping.begin(); it != ip_mac_mapping.end();)
    {
        if (it->first == HostIP)
        {
            // Output with 'L' prefix
            cout << "L" << it->first << " --> " << it->second.first << endl;
            ++it;
            continue;
        }
        auto duration = chrono::duration_cast<chrono::seconds>(now - it->second.second).count();
        if (duration > 30)
            it = ip_mac_mapping.erase(it);
        else
        {
            cout << it->first << " --> " << it->second.first << endl;
            ++it;
        }
    }
    cout << endl;
}

void getLocalMac(pcap_t* adhandle, ARPFrame arp_frame)
{
    pcap_pkthdr*  packet_header;
    const u_char* packet_data;
    Data*         packet;
    int           res = 0;

    for (int i = 0; i < 6; i++)
    {
        arp_frame.FrameHeader.DesMAC[i] = 0xff;
        arp_frame.FrameHeader.SrcMAC[i] = i;
        arp_frame.SendHa[i]             = i;
        arp_frame.RecvHa[i]             = 0x00;
    }
    arp_frame.SendIP = inet_addr("114.51.41.91");
    arp_frame.RecvIP = inet_addr(HostIP.c_str());

    pcap_sendpacket(adhandle, (u_char*)&arp_frame, sizeof(ARPFrame));

    while ((res = pcap_next_ex(adhandle, &packet_header, &packet_data)) >= 0)
    {
        if (res == 0) continue;

        packet = (Data*)packet_data;
        if (iptos(packet->IPHeader.SrcIP) == HostIP)
        {
            for (int i = 0; i < 6; i++) { HostMAC[i] = packet->FrameHeader.SrcMAC[i]; }
            char mac_addr[18];
            sprintf(mac_addr,
                "%02X-%02X-%02X-%02X-%02X-%02X",
                (unsigned int)HostMAC[0],
                (unsigned int)HostMAC[1],
                (unsigned int)HostMAC[2],
                (unsigned int)HostMAC[3],
                (unsigned int)HostMAC[4],
                (unsigned int)HostMAC[5]);
            ip_mac_mapping[HostIP] = {mac_addr, chrono::steady_clock::now()};
            break;
        }
    }
}

int getMac(pcap_t* adhandle, ARPFrame arp_frame)
{
    pcap_pkthdr*  packet_header;
    const u_char* packet_data;
    int           res = 0;

    cout << "Enter IP address(or q to quit): ";
    string IP;
    cin >> IP;

    if (IP == "q") return 1;
    
    auto it = ip_mac_mapping.find(IP);
    if (it != ip_mac_mapping.end())
    {
        auto duration = chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - it->second.second).count();
        if (duration <= 30)
        {
            print_mapping();
            return 0;
        }
        else ip_mac_mapping.erase(it);
    }

    for (int i = 0; i < 6; i++)
    {
        arp_frame.FrameHeader.DesMAC[i] = 0xff;
        arp_frame.FrameHeader.SrcMAC[i] = HostMAC[i];
        arp_frame.SendHa[i]             = HostMAC[i];
        arp_frame.RecvHa[i]             = 0x00;
    }
    arp_frame.SendIP = inet_addr(HostIP.c_str());
    arp_frame.RecvIP = inet_addr(IP.c_str());

    pcap_sendpacket(adhandle, (u_char*)&arp_frame, sizeof(ARPFrame));

    while ((res = pcap_next_ex(adhandle, &packet_header, &packet_data)) >= 0)
    {
        if (res == 0) continue;

        ARPFrame* ARP_Packet = (ARPFrame*)packet_data;
        string    desIP      = iptos(ARP_Packet->RecvIP);
        string    srcIP      = iptos(ARP_Packet->SendIP);
        if ((desIP == HostIP) && (srcIP == IP))
        {
            uint8_t MACs[6];
            for (int i = 0; i < 6; i++) { MACs[i] = ARP_Packet->FrameHeader.SrcMAC[i]; }

            char mac_addr[18];
            sprintf(mac_addr,
                "%02X-%02X-%02X-%02X-%02X-%02X",
                (unsigned int)MACs[0],
                (unsigned int)MACs[1],
                (unsigned int)MACs[2],
                (unsigned int)MACs[3],
                (unsigned int)MACs[4],
                (unsigned int)MACs[5]);

            ip_mac_mapping[IP] = {mac_addr, chrono::steady_clock::now()};
            break;
        }
    }

    print_mapping();

    return 0;
}

int main()
{
    pcap_t* adhandle = init();
    if (!adhandle) return 1;

    ARPFrame arp_frame;
    MAKE_ARP(arp_frame);

    getLocalMac(adhandle, arp_frame);

    while (!getMac(adhandle, arp_frame));
}