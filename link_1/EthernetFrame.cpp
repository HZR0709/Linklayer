// EthernetFrame.cpp

#include "EthernetFrame.h"

EthernetFrame::EthernetFrame(const uint8_t* dst_mac, const uint8_t* src_mac, uint16_t ethertype, const uint8_t* payload, int payload_len) {
    std::memset(frame, 0, ETHERNET_FRAME_SIZE); // 初始化并清零frame数组
    std::memcpy(frame, dst_mac, 6); // 复制目的MAC地址
    std::memcpy(frame + 6, src_mac, 6); // 复制源MAC地址
    frame[12] = (ethertype >> 8) & 0xFF; // 高位
    frame[13] = ethertype & 0xFF; // 低位
    std::memcpy(frame + ETHERNET_HEADER_SIZE, payload, payload_len); // 复制负载
    frame_size = ETHERNET_HEADER_SIZE + payload_len;
}

uint8_t* EthernetFrame::getFrame() {
    return frame;
}

int EthernetFrame::getFrameSize() {
    return frame_size;
}
