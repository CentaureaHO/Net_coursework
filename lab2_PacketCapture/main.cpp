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

#if defined(__linux__)
#include <termios.h>
#include <unistd.h>

void setNonCanonicalMode(bool enable)
{
    static struct termios oldt, newt;
    if (enable)
    {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    else { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); }
}
#elif defined(_WIN32)
#include <conio.h>
#endif

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

    char buffer[20];
    strftime(buffer, sizeof(buffer), "%m-%d %H:%M:%S", timeinfo);

    ostringstream oss;
    oss << buffer << "." << setw(2) << setfill('0') << (ts.tv_usec / 10000);

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
    }
}

void parsePackets(const vector<pair<struct pcap_pkthdr, vector<u_char>>>& packets)
{
    stringstream oss;
    for (const auto& [header, packet] : packets)
    {
        string formattedTime = formatTimestamp(header.ts);
        oss << "Time: " << formattedTime << " | ";

        oss << "Src MAC: ";
        for (int i = 6; i < 12; ++i) oss << hex << setw(2) << setfill('0') << (int)packet[i] << (i == 11 ? "" : ":");

        oss << " -> Dest MAC: ";
        for (int i = 0; i < 6; ++i) oss << hex << setw(2) << setfill('0') << (int)packet[i] << (i == 5 ? "" : ":");

        uint16_t etherType = (packet[12] << 8) | packet[13];
        oss << " | Type: " << hex << setw(4) << setfill('0') << etherType;

        if (etherType == 0x0800 && packet.size() >= 34)  // IPv4
        {
            oss << " | Src IP: ";
            for (int i = 26; i < 30; ++i) { oss << dec << (int)packet[i] << (i == 29 ? "" : "."); }

            oss << " -> Dest IP: ";
            for (int i = 30; i < 34; ++i) { oss << dec << (int)packet[i] << (i == 33 ? "" : "."); }
        }
        else if (etherType == 0x86DD && packet.size() >= 54)  // IPv6
        {
            oss << " | Src IP: ";
            for (int i = 22; i < 38; ++i)
            {
                oss << hex << setw(2) << setfill('0') << (int)packet[i] << (i % 2 == 1 && i < 37 ? ":" : "");
            }

            oss << " -> Dest IP: ";
            for (int i = 38; i < 54; ++i)
            {
                oss << hex << setw(2) << setfill('0') << (int)packet[i] << (i % 2 == 1 && i < 53 ? ":" : "");
            }
        }

        oss << "\n";
    }
    cout << oss.str();
    fflush(stdout);
}

void parseThread()
{
    while (running)
    {
        unique_lock<mutex> lock(queueMutex);
        queueCondVar.wait(lock, [] { return (!packetQueue.empty() && !paused) || !running; });

        if (!packetQueue.empty() && !paused)
        {
            auto packets = std::move(packetQueue.front());
            packetQueue.pop_front();
            lock.unlock();

            parsePackets(packets);
        }
        else if (!running) { break; }

        this_thread::sleep_for(chrono::milliseconds(100));
    }
}

void controlThread()
{
    while (running)
    {
        char command = '\0';

#if defined(__linux__)
        setNonCanonicalMode(true);
        command = getchar();
        setNonCanonicalMode(false);
#elif defined(_WIN32)
        if (_kbhit()) { command = _getch(); }
#endif

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
            cout << "Exiting and returning to device selection..." << endl;
            queueCondVar.notify_all();
            pauseCondVar.notify_all();
            break;
        }
        this_thread::sleep_for(chrono::milliseconds(100));
    }
}

int main()
{
    NetDevice netDevice;
    while (running)
    {
#if defined(__linux__)
        system("clear");
#elif defined(_WIN32)
        system("cls");
#endif

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

        char entry       = '\0';
        int  choice      = -1;
        int  deviceCount = static_cast<int>(devices.size());

        while (choice < 0 || choice >= deviceCount)
        {
            cout << "Select a device(by idx) or q to exit: ";
            cin >> entry;
            if (entry == 'q') { return 0; }
            choice = entry - '1';
        }

        packetQueue.clear();

        netDevice.selectDevice(devices[choice].name);
        netDevice.openDevice();

        thread capture(captureThread, ref(netDevice));
        thread parse(parseThread);
        thread control(controlThread);

        control.join();
        capture.join();
        parse.join();

        netDevice.closeDevice();

        if (!running) { running = true; }
    }
}
