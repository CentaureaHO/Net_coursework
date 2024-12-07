#include <net/net_devs.h>
#include <cstring>
#include <iostream>
using namespace std;

class DeviceManager
{
  private:
    DeviceManager();
    ~DeviceManager();

  public:
    static DeviceManager& getInstance();

    DeviceManager(const DeviceManager&)            = delete;
    DeviceManager& operator=(const DeviceManager&) = delete;

  private:
    pcap_if_t*      __devs;
    struct ifaddrs* __ifap;

  public:
    pcap_if_t* getDeviceHandle(const string& deviceName);
    pcap_if_t* getDeviceHandle();
    void       getLocalIPs(pcap_if_t* dev, vector<pair<string, uint8_t>>& ips);
};

DeviceManager::DeviceManager() : __devs(nullptr), __ifap(nullptr)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&__devs, errbuf) == -1)
    {
        cerr << "Error finding devices: " << errbuf << endl;
        exit(1);
    }

    if (getifaddrs(&__ifap) == -1)
    {
        perror("getifaddrs");
        pcap_freealldevs(__devs);
        exit(1);
    }
}
DeviceManager::~DeviceManager()
{
    if (__devs) pcap_freealldevs(__devs);
    if (__ifap) freeifaddrs(__ifap);

    __devs = nullptr;
    __ifap = nullptr;
}

DeviceManager& DeviceManager::getInstance()
{
    static DeviceManager instance;
    return instance;
}

pcap_if_t* DeviceManager::getDeviceHandle(const string& deviceName)
{
    pcap_if_t* d;
    for (d = __devs; d != nullptr; d = d->next)
        if (deviceName == d->name) break;

    if (d == nullptr)
    {
        cerr << "Device " << deviceName << " not found." << endl;
        return nullptr;
    }

    return d;
}

pcap_if_t* DeviceManager::getDeviceHandle()
{
    pcap_if_t*         dev   = __devs;
    int                index = 0;
    vector<pcap_if_t*> deviceList;

    cout << "Available devices:" << endl;
    while (dev != nullptr)
    {
        cout << index++ << ". " << dev->name;
        if (dev->description) cout << " - " << dev->description;
        cout << endl;
        deviceList.push_back(dev);
        dev = dev->next;
    }

    index = -1;
    while (index < 0 || index >= static_cast<int>(deviceList.size()))
    {
        cout << "Enter a device number: ";
        cin >> index;
    }

    return deviceList[index];
}

void DeviceManager::getLocalIPs(pcap_if_t* dev, vector<pair<string, uint8_t>>& ips)
{
    struct ifaddrs*     ifa = __ifap;
    struct sockaddr_in* sa  = nullptr;
    char                ip_str[INET_ADDRSTRLEN];
    char                mask_str[INET_ADDRSTRLEN];
    uint8_t             default_mask_val = 32;

    while (ifa != nullptr)
    {
        if (strcmp(ifa->ifa_name, dev->name) != 0 || ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET)
        {
            ifa = ifa->ifa_next;
            continue;
        }
        sa = (struct sockaddr_in*)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &(sa->sin_addr), ip_str, sizeof(ip_str)) == nullptr)
        {
            perror("inet_ntop");
            ifa = ifa->ifa_next;
            continue;
        }

        ips.emplace_back(ip_str, default_mask_val);
        auto& ip = ips.back();

        if (ifa->ifa_netmask != nullptr)
        {
            sa = (struct sockaddr_in*)ifa->ifa_netmask;
            if (inet_ntop(AF_INET, &(sa->sin_addr), mask_str, sizeof(mask_str)) == nullptr)
            {
                perror("inet_ntop");
                ifa = ifa->ifa_next;
                continue;
            }

            uint8_t hi, mi, lo, la;
            if (sscanf(mask_str, "%hhu.%hhu.%hhu.%hhu", &hi, &mi, &lo, &la) != 4)
            {
                cerr << "Error parsing netmask" << endl;
                ifa = ifa->ifa_next;
                continue;
            }

            uint32_t mask_int = (hi << 24) | (mi << 16) | (lo << 8) | la;
            uint8_t& cnt      = ip.second;
            cnt               = 0;
            for (mi = 31; mi < 32; --mi)
            {
                if (mask_int & (1 << mi))
                    ++cnt;
                else
                    break;
            }
        }
        ifa = ifa->ifa_next;
    }
}

namespace
{
    DeviceManager& manager = DeviceManager::getInstance();
}

pcap_if_t* getDevice(string dev_name) { return manager.getDeviceHandle(dev_name); }
pcap_if_t* getDevice() { return manager.getDeviceHandle(); }
void getLocalIPs(pcap_if_t* dev, std::vector<std::pair<std::string, uint8_t>>& ips) { manager.getLocalIPs(dev, ips); }