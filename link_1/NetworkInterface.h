#ifndef NETWORK_INTERFACE_H
#define NETWORK_INTERFACE_H

#include <cstdint>
#include <string>
#include <netinet/in.h>
#include "EthernetFrame.h"
#include "ARP.h"
#include "IP.h"
#include "TCPHeader.h"
#include "UDPHeader.h"

class NetworkInterface {
public:
    NetworkInterface(const std::string& interface_name, uint32_t src_ip, const uint8_t* src_mac);
    ~NetworkInterface();

    bool sendARPRequest(uint32_t target_ip, const uint8_t* target_mac);
    bool receiveARPReply(uint32_t target_ip, uint8_t* target_mac);
    bool sendARPReply(uint32_t target_ip, const uint8_t* target_mac);
    bool sendICMPEchoRequest(uint32_t dest_ip, const uint8_t* dest_mac, uint16_t id, uint16_t sequence);
    bool receiveICMPEchoReply(uint32_t dest_ip, uint16_t id, uint16_t sequence, int& bytes, int& ttl);
    void sendPing(uint32_t dest_ip);

     // TCP相关方法
    bool sendTCPHandshake(uint32_t dest_ip, uint16_t dest_port);
    bool receiveTCPHandshake(uint32_t& seq_num, uint32_t& ack_num);
    bool sendTCPAck(uint32_t dest_ip, uint16_t dest_port, uint32_t seq_num, uint32_t ack_num);
    
    // UDP相关方法
    bool sendUDPMessage(uint32_t dest_ip, uint16_t dest_port, const std::string& message);
    bool receiveUDPMessage(uint32_t& src_ip, uint16_t& src_port, std::string& message);

private:
    std::string interface_name;
    int sockfd;
    int ifindex;
    uint32_t src_ip;
    const uint8_t* src_mac;

    bool initialize();
    void cleanup();
    bool getInterfaceIndex();
    bool bindSocket();
};

#endif // NETWORK_INTERFACE_H
