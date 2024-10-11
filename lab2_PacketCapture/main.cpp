#include <chrono>
#include <condition_variable>
#include <ctime>
#include <deque>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

#include <net_devs.h>

#define GAP_TIME 1000  // 1000ms

using namespace std;

deque<vector<pair<struct pcap_pkthdr, vector<u_char>>>> packetQueue;
mutex                                                   queueMutex;
condition_variable                                      queueCondVar;
condition_variable                                      pauseCondVar;
bool                                                    paused  = false;
bool                                                    running = true;

string formatTimestamp(const timeval& ts)
{
    time_t rawtime  = ts.tv_sec;
    tm*    timeinfo = localtime(&rawtime);

    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    ostringstream oss;
    oss << buffer << "." << setw(6) << setfill('0') << ts.tv_usec;

    return oss.str();
}

void captureThread(NetDevice& netDevice)
{
    while (running)
    {
        unique_lock<mutex> lock(queueMutex);
        pauseCondVar.wait(lock, [] { return !paused || !running; });

        if (!running) break;

        lock.unlock();
        vector<pair<struct pcap_pkthdr, vector<u_char>>> packets = netDevice.capturePackets(10);

        {
            lock_guard<mutex> lock(queueMutex);
            packetQueue.push_back(std::move(packets));
        }
        queueCondVar.notify_one();

        this_thread::sleep_for(chrono::milliseconds(GAP_TIME));
    }
}

void parsePackets(const vector<pair<struct pcap_pkthdr, vector<u_char>>>& packets)
{
    for (const auto& [header, packet] : packets)
    {
        string formattedTime = formatTimestamp(header.ts);
        cout << "Time: " << formattedTime << " | ";

        cout << "Source MAC: ";
        for (int i = 6; i < 12; ++i)
        {
            cout << hex << setw(2) << setfill('0') << (int)packet[i] << (i == 11 ? "" : ":");
        }

        cout << " -> Destination MAC: ";
        for (int i = 0; i < 6; ++i) { cout << hex << setw(2) << setfill('0') << (int)packet[i] << (i == 5 ? "" : ":"); }

        cout << endl;
    }
}

void parseThread()
{
    while (running)
    {
        unique_lock<mutex> lock(queueMutex);
        queueCondVar.wait(lock, [] { return !packetQueue.empty() || !running; });

        if (!packetQueue.empty())
        {
            auto packets = std::move(packetQueue.front());
            packetQueue.pop_front();
            lock.unlock();

            parsePackets(packets);
        }
        else if (!running) { break; }
    }
}

void controlThread()
{
    while (running)
    {
        char command;
        cin >> command;

        if (command == 'p')
        {
            paused = true;
            cout << "Capturing paused." << endl;
        }
        else if (command == 'r')
        {
            {
                lock_guard<mutex> lock(queueMutex);
                paused = false;
            }
            cout << "Capturing resumed." << endl;
            pauseCondVar.notify_all();
        }
        else if (command == 'q')
        {
            {
                lock_guard<mutex> lock(queueMutex);
                running = false;
                paused  = false;
            }
            cout << "Exiting..." << endl;
            queueCondVar.notify_all();
            pauseCondVar.notify_all();
            break;
        }
    }
}

int main()
{
    NetDevice netDevice;

    const vector<NetDevice::DeviceInfo>& devices = NetDevice::getDevices();
    if (devices.empty())
    {
        cerr << "No network devices detected" << endl;
        return 1;
    }

    cout << "Available Devices:" << endl;
    for (size_t i = 0; i < devices.size(); ++i)
    {
        cout << i + 1 << ": " << devices[i].name << " (" << devices[i].description << ")" << endl;
    }
    int choice = -1;
    int deviceCount = static_cast<int>(devices.size());
    while (choice < 0 || choice >= deviceCount)
    {
        cout << "Select a device(by idx): ";
        cin >> choice;
        choice = choice - 1;
    }

    netDevice.selectDevice(devices[4].name);

    netDevice.openDevice();

    thread capture(captureThread, ref(netDevice));
    thread parse(parseThread);
    thread control(controlThread);

    control.join();
    capture.join();
    parse.join();

    netDevice.closeDevice();
}