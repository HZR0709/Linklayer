#ifndef TCPHEADER_H
#define TCPHEADER_H

#include <cstdint>

struct TCPHeader {
    uint16_t src_port;      // 源端口
    uint16_t dest_port;     // 目的端口
    uint32_t seq_num;       // 序列号
    uint32_t ack_num;       // 确认号
    uint8_t  data_offset;   // 数据偏移
    uint8_t  flags;         // 标志
    uint16_t window_size;   // 窗口大小
    uint16_t checksum;      // 校验和
    uint16_t urgent_ptr;    // 紧急指针

    // TCP标志位
    enum {
        FIN = 1 << 0,
        SYN = 1 << 1,
        RST = 1 << 2,
        PSH = 1 << 3,
        ACK = 1 << 4,
        URG = 1 << 5,
        ECE = 1 << 6,
        CWR = 1 << 7
    };
};

#endif // TCPHEADER_H
