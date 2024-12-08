#ifndef __STRUCT_ARP_TABLE_H__
#define __STRUCT_ARP_TABLE_H__

#include <common/lock.h>
#include <net/package.h>
#include <atomic>
#include <chrono>
#include <stdint.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

class ARP_Table
{
  public:
    struct Entry
    {
        std::chrono::steady_clock::time_point timestamp;
        uint8_t                               mac[6];
    };

  private:
    ReWrLock                               lock;
    std::unordered_map<std::string, Entry> arp_table;

    std::atomic<bool> running;
    std::thread       cleanup_thread;
    

  public:
    ARP_Table();
    ~ARP_Table();

    void insert(const std::string& ip, const uint8_t* mac);
    bool lookup(const std::string& ip, uint8_t* mac);
    void print();

  private:
    void clean_outdated_entries();
};

#endif