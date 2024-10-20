#include <iostream>
#include <stdexcept>

#include <net_devs.h>

using namespace std;

vector<NetDevice::DeviceInfo> NetDevice::_devices = {};

bool NetDevice::_devices_initialized = false;

NetDevice::NetDevice() : _device_handle(nullptr)
{
    if (!_devices_initialized)
    {
        updateDevices();
        _devices_initialized = true;
    }
}

NetDevice::~NetDevice() { closeDevice(); }

const vector<NetDevice::DeviceInfo>& NetDevice::getDevices()
{
    if (!_devices_initialized)
    {
        updateDevices();
        _devices_initialized = true;
    }
    return _devices;
}

void NetDevice::updateDevices()
{
    char       errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    _devices.clear();

    if (pcap_findalldevs(&alldevs, errbuf) == -1) { throw runtime_error("Error finding devices: " + string(errbuf)); }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        DeviceInfo info;
        info.name        = d->name;
        info.description = d->description ? d->description : "No available description";
        _devices.push_back(info);
    }

    pcap_freealldevs(alldevs);
}

void NetDevice::selectDevice(const string& deviceName) { _device_name = deviceName; }

string NetDevice::getCurDeviceName() const { return _device_name; }

void NetDevice::openDevice()
{
    if (_device_name.empty()) { throw runtime_error("No device selected"); }

    char errbuf[PCAP_ERRBUF_SIZE];
    _device_handle = pcap_open_live(_device_name.c_str(), 64, 1, 1000, errbuf);
    if (_device_handle == nullptr) { throw runtime_error("Error opening device: " + string(errbuf)); }
}

pcap_t* NetDevice::getDeviceHandle() const { return _device_handle; }

vector<pair<struct pcap_pkthdr, vector<u_char>>> NetDevice::capturePackets(int packet_count)
{
    if (_device_handle == nullptr) { throw runtime_error("Device not opened"); }

    vector<pair<struct pcap_pkthdr, vector<u_char>>> capturedPackets;
    pcap_loop(_device_handle, packet_count, packetCollector, reinterpret_cast<u_char*>(&capturedPackets));
    return capturedPackets;
}

void NetDevice::stopCapture()
{
    if (_device_handle != nullptr) { pcap_breakloop(_device_handle); }
}

void NetDevice::closeDevice()
{
    if (_device_handle != nullptr)
    {
        pcap_close(_device_handle);
        _device_handle = nullptr;
    }
}

void NetDevice::packetCollector(u_char* userData, const struct pcap_pkthdr* packetHeader, const u_char* packet)
{
    auto* capturedPackets = reinterpret_cast<vector<pair<struct pcap_pkthdr, vector<u_char>>>*>(userData);
    capturedPackets->emplace_back(*packetHeader, vector<u_char>(packet, packet + packetHeader->len));
}