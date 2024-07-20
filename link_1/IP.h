#ifndef IP_H
#define IP_H

#include <cstdint>
#include <netinet/in.h>
#include <arpa/inet.h>

#define IP_HEADER_SIZE 20
#define ICMP_HEADER_SIZE 8

struct IPHeader {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed));

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));

class IP {
public:
    static void createIPHeader(IPHeader& ip, uint32_t src_ip, uint32_t dest_ip, uint16_t total_length, uint8_t protocol);
    static uint16_t calculateChecksum(const void* data, int length);
};

class ICMP {
public:
    static void createEchoRequest(ICMPHeader& icmp, uint16_t id, uint16_t sequence);
    static bool isEchoReply(const ICMPHeader& icmp, uint16_t id, uint16_t sequence);
};

#endif // IP_H
