#ifndef UDPHEADER_H
#define UDPHEADER_H

#include <cstdint>

struct UDPHeader {
    uint16_t src_port;  // 源端口
    uint16_t dest_port; // 目的端口
    uint16_t length;    // 长度
    uint16_t checksum;  // 校验和
};

#endif // UDPHEADER_H
