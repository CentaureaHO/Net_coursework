#include <struct/arp_table.h>
#include <cstring>
using namespace std;
using namespace chrono;

ARP_Table::ARP_Table() : running(true), cleanup_thread(&ARP_Table::clean_outdated_entries, this) {}
ARP_Table::~ARP_Table()
{
    running = false;
    cleanup_thread.join();
}

void ARP_Table::clean_outdated_entries()
{
    while (running)
    {
        {
            WriteGuard guard = lock.write();
            auto       now   = steady_clock::now();
            for (auto it = arp_table.begin(); it != arp_table.end();)
            {
                auto duration = duration_cast<seconds>(now - it->second.timestamp);
                if (duration.count() > 10)
                    it = arp_table.erase(it);
                else
                    ++it;
            }
        }
        this_thread::sleep_for(seconds(1));
    }
}

void ARP_Table::insert(const string& ip, const uint8_t* mac)
{
    WriteGuard guard = lock.write();
    arp_table[ip]    = {steady_clock::now(), {mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}};
}

bool ARP_Table::lookup(const string& ip, uint8_t* mac)
{
    ReadGuard guard = lock.read();
    auto      it    = arp_table.find(ip);
    if (it != arp_table.end())
    {
        memcpy(mac, it->second.mac, 6);
        return true;
    }
    return false;
}

void ARP_Table::print()
{
    ReadGuard guard = lock.read();
    for (auto& [ip, entry] : arp_table)
    {
        printf("\t%s -> %02X-%02X-%02X-%02X-%02X-%02X\n",
            ip.c_str(),
            entry.mac[0],
            entry.mac[1],
            entry.mac[2],
            entry.mac[3],
            entry.mac[4],
            entry.mac[5]);
    }
}