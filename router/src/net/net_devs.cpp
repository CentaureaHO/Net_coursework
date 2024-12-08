#include <net/net_devs.h>
#include <common/log.h>
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
    pcap_if_t* __devs;
#ifndef _WIN32
    struct ifaddrs* __ifap;
#endif

  public:
    pcap_if_t* getDeviceHandle(const string& deviceName);
    pcap_if_t* getDeviceHandle();
    void       getLocalIPs(pcap_if_t* dev, vector<pair<string, uint8_t>>& ips);
};

DeviceManager::DeviceManager() : __devs(nullptr)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&__devs, errbuf) == -1)
    {
        // cerr << "Error finding devices: " << errbuf << endl;
        LOG_ERR(glb_logger, "Error finding devices: ", errbuf);
        exit(1);
    }

#ifndef _WIN32
    if (getifaddrs(&__ifap) == -1)
    {
        // perror("getifaddrs");
        LOG_ERR(glb_logger, "getifaddrs");
        pcap_freealldevs(__devs);
        exit(1);
    }
#endif
}

DeviceManager::~DeviceManager()
{
    if (__devs) pcap_freealldevs(__devs);
#ifndef _WIN32
    if (__ifap) freeifaddrs(__ifap);
#endif

    __devs = nullptr;
#ifndef _WIN32
    __ifap = nullptr;
#endif
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
        // cerr << "Device " << deviceName << " not found." << endl;
        LOG_ERR(glb_logger, "Device ", deviceName, " not found.");
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
        cout << "Enter a device number(or -1 to quit): ";
        cin >> index;
        if (index == -1) return nullptr;
    }

    return deviceList[index];
}

void DeviceManager::getLocalIPs(pcap_if_t* dev, vector<pair<string, uint8_t>>& ips)
{
#ifdef _WIN32
    ULONG                 flags            = GAA_FLAG_INCLUDE_PREFIX;
    ULONG                 family           = AF_INET;
    ULONG                 bufferSize       = 15000;
    PIP_ADAPTER_ADDRESSES adapterAddresses = nullptr;

    DWORD dwRetVal = 0;

    do {
        // cout << "Allocating memory for adapter information..." << endl;
        LOG(glb_logger, "Allocating memory for adapter information...");
        adapterAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
        if (adapterAddresses == nullptr)
        {
            // cerr << "Memory allocation failed for IP_ADAPTER_ADDRESSES struct" << endl;
            LOG_ERR(glb_logger, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct");
            return;
        }

        dwRetVal = GetAdaptersAddresses(family, flags, nullptr, adapterAddresses, &bufferSize);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW)
        {
            free(adapterAddresses);
            adapterAddresses = nullptr;
        }
        else { break; }
    } while (dwRetVal == ERROR_BUFFER_OVERFLOW);

    if (dwRetVal != NO_ERROR)
    {
        // cerr << "GetAdaptersAddresses() failed with error: " << dwRetVal << endl;
        LOG_ERR(glb_logger, "GetAdaptersAddresses() failed with error: ", dwRetVal);
        if (adapterAddresses) free(adapterAddresses);
        return;
    }

    string dev_guid = extract_guid(dev->name);

    PIP_ADAPTER_ADDRESSES adapter = adapterAddresses;
    while (adapter)
    {
        if (!dev_guid.empty() && _stricmp(adapter->AdapterName, dev_guid.c_str()) != 0)
        {
            adapter = adapter->Next;
            continue;
        }

        PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
        while (unicast)
        {
            if (unicast->Address.lpSockaddr->sa_family == AF_INET)
            {
                char         ip_str[INET_ADDRSTRLEN];
                sockaddr_in* sa = (sockaddr_in*)unicast->Address.lpSockaddr;
                if (inet_ntop(AF_INET, &(sa->sin_addr), ip_str, sizeof(ip_str)) == nullptr) { perror("inet_ntop"); }
                else
                {
                    uint8_t prefixLength = unicast->OnLinkPrefixLength;
                    ips.emplace_back(string(ip_str), prefixLength);
                }
            }
            unicast = unicast->Next;
        }

        adapter = adapter->Next;
    }

    if (adapterAddresses) free(adapterAddresses);

#else
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
                // cerr << "Error parsing netmask" << endl;
                LOG_ERR(glb_logger, "Error parsing netmask: ", mask_str);
                ifa = ifa->ifa_next;
                continue;
            }

            uint32_t mask_int = (hi << 24) | (mi << 16) | (lo << 8) | la;
            uint8_t& cnt      = ip.second;
            cnt               = 0;
            for (int mi = 31; mi >= 0; --mi)
            {
                if (mask_int & (1 << mi))
                    ++cnt;
                else
                    break;
            }
        }
        ifa = ifa->ifa_next;
    }
#endif
}

namespace
{
    DeviceManager& manager = DeviceManager::getInstance();
}

pcap_if_t* getDevice(string dev_name) { return manager.getDeviceHandle(dev_name); }
pcap_if_t* getDevice() { return manager.getDeviceHandle(); }
void       getLocalIPs(pcap_if_t* dev, vector<pair<string, uint8_t>>& ips) { manager.getLocalIPs(dev, ips); }