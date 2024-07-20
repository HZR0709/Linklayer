#include "Route.h"

void RoutingTable::addEntry(const std::string &dest_network, const std::string &subnet_mask, const std::string &gateway_ip, const uint8_t *gateway_mac)
{
    RouteEntry entry;
    entry.dest_network = inet_addr(dest_network.c_str());
    entry.subnet_mask = inet_addr(subnet_mask.c_str());
    entry.gateway_ip = inet_addr(gateway_ip.c_str());
    std::memcpy(entry.gateway_mac, gateway_mac, 6);
    routing_table.push_back(entry);
}

bool RoutingTable::findRoute(uint32_t dest_ip, RouteEntry &route)
{
    for (const auto &entry : routing_table)
    {
        if ((dest_ip & entry.subnet_mask) == (entry.dest_network & entry.subnet_mask))
        {
            route = entry;
            return true;
        }
    }
    return false;
}
