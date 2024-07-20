#include <iostream>
#include <cstring>
#include <chrono>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <algorithm>
#include <numeric>
#include "NetworkInterface.h"

int main() {
    const std::string interface = "ens33"; // 网络接口名
    uint32_t src_ip = inet_addr("192.168.0.108");   //src ip
    uint8_t src_mac[6] = {0x00, 0x0c, 0x29, 0x18, 0xc0, 0x11}; // 源mac地址
    NetworkInterface netif(interface, src_ip, src_mac);

    uint32_t dest_ip = inet_addr("192.168.0.106");
    uint16_t id = 1;
    uint16_t sequence = 1;

    // 获取目标MAC地址
    uint8_t target_mac[6];
    if (!netif.sendARPRequest(dest_ip, target_mac) || !netif.receiveARPReply(dest_ip, target_mac)) {
        std::cerr << "Failed to resolve target MAC address." << std::endl;
        return 1;
    }

    // 统计信息
    int packets_sent = 0;
    int packets_received = 0;
    std::vector<int> rtt_times;

    // 发送并接收ICMP Echo请求和响应
    for (int i = 0; i < 4; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        if (!netif.sendICMPEchoRequest(dest_ip, target_mac, id, sequence)) {
            std::cerr << "Failed to send ICMP Echo Request." << std::endl;
        } else {
            packets_sent++;
        }

        int bytes = 0;
        int ttl = 0;
        if (netif.receiveICMPEchoReply(dest_ip, id, sequence, bytes, ttl)) {
            auto end = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            rtt_times.push_back(elapsed);
            packets_received++;
            std::cout << "来自 " << inet_ntoa(*(struct in_addr*)&dest_ip)
                      << " 的回复: 字节=" << bytes << " 时间=" << elapsed << "ms TTL=" << ttl << std::endl;
        } else {
            std::cerr << "Failed to receive ICMP Echo Reply." << std::endl;
        }
        sequence++;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // 计算统计信息
    if (rtt_times.empty()) {
        std::cerr << "No responses received." << std::endl;
        return 1;
    }
    int min_rtt = *std::min_element(rtt_times.begin(), rtt_times.end());
    int max_rtt = *std::max_element(rtt_times.begin(), rtt_times.end());
    double avg_rtt = std::accumulate(rtt_times.begin(), rtt_times.end(), 0.0) / rtt_times.size();

    std::cout << inet_ntoa(*(struct in_addr*)&dest_ip) << " 的 Ping 统计信息:" << std::endl;
    std::cout << "    数据包: 已发送 = " << packets_sent << "，已接收 = " << packets_received
              << "，丢失 = " << packets_sent - packets_received << " ("
              << (packets_sent - packets_received) * 100 / packets_sent << "% 丢失)，" << std::endl;
    std::cout << "往返行程的估计时间(以毫秒为单位):" << std::endl;
    std::cout << "    最短 = " << min_rtt << "ms，最长 = " << max_rtt << "ms，平均 = " << static_cast<int>(avg_rtt) << "ms" << std::endl;

    return 0;
}
