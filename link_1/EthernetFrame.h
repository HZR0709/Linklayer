// EthernetFrame.h

#ifndef ETHERNET_FRAME_H
#define ETHERNET_FRAME_H

#include <cstdint>
#include <cstring>

#define ETHERNET_FRAME_SIZE 1518
#define ETHERNET_HEADER_SIZE 14
#define ETHER_TYPE_IP 0x0800
#define ETHER_TYPE_ARP 0x0806

class EthernetFrame {
public:
    EthernetFrame(const uint8_t* dst_mac, const uint8_t* src_mac, uint16_t ethertype, const uint8_t* payload, int payload_len);
    uint8_t* getFrame();
    int getFrameSize();

private:
    uint8_t frame[ETHERNET_FRAME_SIZE];
    int frame_size;
};

#endif // ETHERNET_FRAME_H
