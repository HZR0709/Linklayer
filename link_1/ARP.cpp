#include "ARP.h"
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include <iomanip>

void ARP::createRequest(ARPMessage &arp, const uint8_t *src_mac, uint32_t src_ip, uint32_t target_ip)
{
    arp.htype = htons(1);      // 以太网
    arp.ptype = htons(0x0800); // IPv4
    arp.hlen = 6;
    arp.plen = 4;
    arp.oper = htons(ARP_REQUEST);
    std::memcpy(arp.sha, src_mac, 6);
    arp.spa = src_ip;
    std::memset(arp.tha, 0, 6);
    arp.tpa = target_ip;

    // Debug output
    // std::cout << "ARP Request Created:\n";
    // std::cout << "Source MAC: ";
    // for (int i = 0; i < 6; ++i) std::cout << std::hex << (int)src_mac[i] << " ";
    // std::cout << "\nSource IP: " << inet_ntoa(*(struct in_addr*)&src_ip) << "\n";
    // std::cout << "Target IP: " << inet_ntoa(*(struct in_addr*)&target_ip) << "\n";
}

void ARP::createReply(ARPMessage &arp, const uint8_t *src_mac, uint32_t src_ip, const uint8_t *target_mac, uint32_t target_ip)
{
    arp.htype = htons(1);      // 以太网
    arp.ptype = htons(0x0800); // IPv4
    arp.hlen = 6;
    arp.plen = 4;
    arp.oper = htons(ARP_REPLY);
    std::memcpy(arp.sha, src_mac, 6);
    arp.spa = src_ip;
    std::memcpy(arp.tha, target_mac, 6);
    arp.tpa = target_ip;
}

ARPCache &ARPCache::get_instance()
{
    static ARPCache instance;
    return instance;
}

void ARPCache::addEntry(uint32_t ip, const uint8_t *mac)
{
    auto it = cache.find(ip);
    if (it != cache.end())
    {
        std::memcpy(it->second, mac, 6);
    }
    else
    {
        std::memcpy(cache[ip], mac, 6);
    }
}

bool ARPCache::get_Mac(uint32_t ip, uint8_t *mac)
{
    if (cache.find(ip) != cache.end())
    {
        std::memcpy(mac, cache[ip], 6);
        return true;
    }
    return false;
}

std::string ARPCache::formatIP(uint32_t ip)
{
    ip = ntohl(ip); // Convert from network byte order to host byte order
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

std::string ARPCache::formatMAC(const uint8_t *mac)
{
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i)
    {
        if (i > 0)
            oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    return oss.str();
}

void ARPCache::printCache() const
{
    std::cout << "[ARP Cache:]" << std::endl;
    for (const auto &entry : cache)
    {
        std::cout << "            IP: " << formatIP(entry.first) << " - MAC: " << formatMAC(entry.second) << std::endl;
    }
}