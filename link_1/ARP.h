#ifndef ARP_FRAME_H
#define ARP_FRAME_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <unordered_map>

#define ARP_REQUEST 1
#define ARP_REPLY 2

struct ARPMessage {
    uint16_t htype; // 硬件类型
    uint16_t ptype; // 协议类型
    uint8_t hlen; // 硬件地址长度
    uint8_t plen; // 协议地址长度
    uint16_t oper; // 操作码 (请求或响应)
    uint8_t sha[6]; // 发送方硬件地址
    uint32_t spa; // 发送方协议地址
    uint8_t tha[6]; // 目标硬件地址
    uint32_t tpa; // 目标协议地址
} __attribute__((packed));

class ARP {
public:
    static void createRequest(ARPMessage& arp, const uint8_t* src_mac, uint32_t src_ip, uint32_t target_ip);
    static void createReply(ARPMessage& arp, const uint8_t* src_mac, uint32_t src_ip, const uint8_t* target_mac, uint32_t target_ip);
};

class ARPCache {
public:
    static ARPCache& get_instance();
    
    ARPCache(const ARPCache&) = delete;
    ARPCache& operator=(const ARPCache&) = delete;
    void addEntry(uint32_t ip, const uint8_t* mac);
    bool get_Mac(uint32_t ip, uint8_t* mac);
    void printCache() const;
    
private:
    ARPCache() = default;    
    std::unordered_map<uint32_t, uint8_t[6]> cache;
    static std::string formatIP(uint32_t ip);
    static std::string formatMAC(const uint8_t *mac);
};

#endif // ARP_FRAME_H
