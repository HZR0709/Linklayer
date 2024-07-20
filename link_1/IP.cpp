#include "IP.h"
#include <cstring>

void IP::createIPHeader(IPHeader& ip, uint32_t src_ip, uint32_t dest_ip, uint16_t total_length, uint8_t protocol) {
    ip.version_ihl = (4 << 4) | (IP_HEADER_SIZE / 4);
    ip.tos = 0;
    ip.total_length = htons(total_length);
    ip.id = htons(0);
    ip.flags_offset = htons(0);
    ip.ttl = 64;
    ip.protocol = protocol;
    ip.checksum = 0;
    ip.src_ip = src_ip;
    ip.dest_ip = dest_ip;
    ip.checksum = calculateChecksum(&ip, IP_HEADER_SIZE);
}

uint16_t IP::calculateChecksum(const void* data, int length) {
    const uint16_t* buffer = (const uint16_t*)data;
    uint32_t sum = 0;

    for (int i = 0; i < length / 2; ++i) {
        sum += buffer[i];
    }

    if (length % 2) {
        sum += ((const uint8_t*)data)[length - 1];
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

void ICMP::createEchoRequest(ICMPHeader& icmp, uint16_t id, uint16_t sequence) {
    icmp.type = 8;
    icmp.code = 0;
    icmp.id = htons(id);
    icmp.sequence = htons(sequence);
    icmp.checksum = 0;
    icmp.checksum = IP::calculateChecksum(&icmp, ICMP_HEADER_SIZE);
}

bool ICMP::isEchoReply(const ICMPHeader& icmp, uint16_t id, uint16_t sequence) {
    return icmp.type == 0 && ntohs(icmp.id) == id && ntohs(icmp.sequence) == sequence;
}
