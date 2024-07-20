#ifndef ROUTE_H
#define ROUTE_H

#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <string>
#include <cstring>

struct RouteEntry {
    uint32_t dest_network;  // 目的网络
    uint32_t subnet_mask;   // 子网掩码
    uint32_t gateway_ip;    // 网关IP地址
    uint8_t gateway_mac[6]; // 网关MAC地址
};

class RoutingTable {
public:
    void addEntry(const std::string& dest_network, const std::string& subnet_mask, const std::string& gateway_ip, const uint8_t* gateway_mac);

    bool findRoute(uint32_t dest_ip, RouteEntry& route);

private:
    std::vector<RouteEntry> routing_table;
};

#endif //ROUTE_H
