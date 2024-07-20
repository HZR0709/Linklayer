#include "NetworkInterface.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <vector>
#include <chrono>
#include <bitset>

NetworkInterface::NetworkInterface(const std::string &interface_name, uint32_t src_ip, const uint8_t *src_mac)
    : interface_name(interface_name), src_ip(src_ip), src_mac(src_mac), sockfd(-1), ifindex(-1)
{
    if (!initialize())
    {
        std::cerr << "初始化网络接口失败。" << std::endl;
    }
}

NetworkInterface::~NetworkInterface()
{
    cleanup();
}

bool NetworkInterface::initialize()
{
    if (!getInterfaceIndex() || !bindSocket())
    {
        return false;
    }
    return true;
}

void NetworkInterface::cleanup()
{
    if (sockfd != -1)
    {
        close(sockfd);
    }
}

bool NetworkInterface::getInterfaceIndex()
{
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1)
    {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
    {
        perror("ioctl");
        close(sockfd);
        sockfd = -1;
        return false;
    }
    ifindex = ifr.ifr_ifindex;
    return true;
}

bool NetworkInterface::bindSocket()
{
    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        perror("bind");
        close(sockfd);
        sockfd = -1;
        return false;
    }
    return true;
}

bool NetworkInterface::sendARPRequest(uint32_t target_ip, const uint8_t *target_mac)
{
    ARPMessage arp_request;
    ARP::createRequest(arp_request, src_mac, src_ip, target_ip);
    EthernetFrame arp_frame(target_mac, src_mac, ETHER_TYPE_ARP, reinterpret_cast<uint8_t *>(&arp_request), sizeof(ARPMessage));

    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    std::memcpy(sa.sll_addr, target_mac, 6);
    sa.sll_halen = 6;

    if (sendto(sockfd, arp_frame.getFrame(), arp_frame.getFrameSize(), 0, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        perror("sendto");
        return false;
    }
    std::cout << "[ ARP ] 发送 请求: " << inet_ntoa(*(struct in_addr *)&src_ip) << "-->" << inet_ntoa(*(struct in_addr *)&target_ip) << std::endl;
    return true;
}

bool NetworkInterface::sendARPReply(uint32_t target_ip, const uint8_t *target_mac)
{
    ARPMessage arp_reply;
    ARP::createReply(arp_reply, src_mac, src_ip, target_mac, target_ip);
    EthernetFrame arp_frame(target_mac, src_mac, ETHER_TYPE_ARP, reinterpret_cast<uint8_t *>(&arp_reply), sizeof(ARPMessage));

    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    std::memcpy(sa.sll_addr, target_mac, 6);
    sa.sll_halen = 6;

    if (sendto(sockfd, arp_frame.getFrame(), arp_frame.getFrameSize(), 0, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        perror("sendto");
        return false;
    }
    std::cout << "[ ARP ] 发送 应答: " << src_ip << "-->" << target_ip << std::endl;
    return true;
}

bool NetworkInterface::receiveARPReply(uint32_t sender_ip, uint8_t *sender_mac)
{
    while (true)
    {
        uint8_t buffer[ETHERNET_FRAME_SIZE];
        int num_bytes = recvfrom(sockfd, buffer, ETHERNET_FRAME_SIZE, 0, NULL, NULL);
        if (num_bytes == -1)
        {
            perror("recvfrom");
            return false;
        }
        // std::cout << "[ Ethernet ] 接收到以太网帧 " << num_bytes << " bytes." << std::endl;

        uint16_t ethertype = (buffer[12] << 8) | buffer[13];
        if (ethertype == ETHER_TYPE_ARP)
        { // ARP帧
            ARPMessage *arp_message = reinterpret_cast<ARPMessage *>(buffer + ETHERNET_HEADER_SIZE);

            std::cout << "[ ARP ] 收到的ARP消息:\n";
            std::cout << "        操作码: " << ntohs(arp_message->oper) << "\n";
            std::cout << "        发送方Mac地址: ";
            for (int i = 0; i < 6; ++i)
                std::cout << std::hex << (int)arp_message->sha[i] << " ";
            std::cout << "\n        发送方IP地址: " << inet_ntoa(*(struct in_addr *)&arp_message->spa) << "\n";
            std::cout << "        目标Mac地址: ";
            for (int i = 0; i < 6; ++i)
                std::cout << std::hex << (int)arp_message->tha[i] << " ";
            std::cout << "\n        目标IP地址: " << inet_ntoa(*(struct in_addr *)&arp_message->tpa) << "\n";

            if (ntohs(arp_message->oper) == ARP_REPLY && arp_message->tpa == src_ip)
            {

                std::cout << "        收到来自 [IP: " << inet_ntoa(*(struct in_addr *)&arp_message->spa) << "] 的ARP应答，保存至ARP缓存表。" << std::endl;
                std::memcpy(sender_mac, arp_message->sha, 6);
                sender_ip = arp_message->spa;
                ARPCache::get_instance().addEntry(arp_message->spa, sender_mac);
                ARPCache::get_instance().printCache();
                return true;
            }
            else if (ntohs(arp_message->oper) == ARP_REQUEST && arp_message->tpa == src_ip)
            {
                std::cout << "        收到来自 [IP: " << inet_ntoa(*(struct in_addr *)&arp_message->spa) << "] 的ARP请求，发送ARP应答。" << std::endl;
                // 发送ARP回复
                sendARPReply(arp_message->tpa, arp_message->tha);
            }
            else
            {
                std::cout << "[ ARP ] 收到非相关ARP消息，丢弃。" << std::endl;
            }
        }
    }

    return false;
}

bool NetworkInterface::sendICMPEchoRequest(uint32_t dest_ip, const uint8_t *dest_mac, uint16_t id, uint16_t sequence)
{
    uint8_t buffer[ETHERNET_FRAME_SIZE];
    std::memset(buffer, 0, ETHERNET_FRAME_SIZE);

    IPHeader ip_header;
    ICMPHeader icmp_header;

    ICMP::createEchoRequest(icmp_header, id, sequence);
    IP::createIPHeader(ip_header, src_ip, dest_ip, IP_HEADER_SIZE + ICMP_HEADER_SIZE, IPPROTO_ICMP);

    std::memcpy(buffer + ETHERNET_HEADER_SIZE, &ip_header, IP_HEADER_SIZE);
    std::memcpy(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE, &icmp_header, ICMP_HEADER_SIZE);

    EthernetFrame icmp_frame(dest_mac, src_mac, ETHER_TYPE_IP, buffer + ETHERNET_HEADER_SIZE, IP_HEADER_SIZE + ICMP_HEADER_SIZE);

    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    std::memcpy(sa.sll_addr, dest_mac, 6);
    sa.sll_halen = 6;

    if (sendto(sockfd, icmp_frame.getFrame(), icmp_frame.getFrameSize(), 0, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        perror("sendto");
        return false;
    }
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_ip, target_ip, INET_ADDRSTRLEN);
    // std::cout << "[ ICMP ] 向 [IP:" << target_ip << "] 发送回声请求" << std::endl;
    return true;
}

bool NetworkInterface::receiveICMPEchoReply(uint32_t dest_ip, uint16_t id, uint16_t sequence, int &bytes, int &ttl)
{
    uint8_t buffer[ETHERNET_FRAME_SIZE];
    fd_set read_fds;
    struct timeval timeout;

    while (true)
    {
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);

        timeout.tv_sec = 1; // 1秒超时
        timeout.tv_usec = 0;

        int ret = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (ret == -1)
        {
            perror("select");
            return false;
        }
        else if (ret == 0)
        {
            std::cerr << "接收超时。" << std::endl;
            return false;
        }

        int num_bytes = recvfrom(sockfd, buffer, ETHERNET_FRAME_SIZE, 0, NULL, NULL);
        if (num_bytes == -1)
        {
            perror("recvfrom");
            return false;
        }

        IPHeader *ip_header = reinterpret_cast<IPHeader *>(buffer + ETHERNET_HEADER_SIZE);
        if (ip_header->protocol == IPPROTO_ICMP && ip_header->src_ip == dest_ip && ip_header->dest_ip == src_ip)
        {
            ICMPHeader *icmp_header = reinterpret_cast<ICMPHeader *>(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
            if (ICMP::isEchoReply(*icmp_header, id, sequence))
            {
                bytes = num_bytes - ETHERNET_HEADER_SIZE;
                ttl = ip_header->ttl;
                // 打印接收到的整个IP数据包（包括IP头和ICMP数据包）
                // std::cout << "Received IP packet: ";
                // for (int i = 0; i < ntohs(ip_header->total_length); ++i) {
                //     std::cout << std::hex << static_cast<int>(buffer[ETHERNET_HEADER_SIZE + i]) << " ";
                // }
                // std::cout << std::dec << std::endl;
                // std::cout << "[ ICMP ] 接收到来自 [IP:" << inet_ntoa(*(struct in_addr*)&ip_header->src_ip) << "] 的回声应答。" << std::endl;
                return true;
            }
        }
    }

    return false;
}

void NetworkInterface::sendPing(uint32_t dest_ip)
{
    int sent = 0, received = 0;
    std::vector<int> times;
    const int numPings = 4;
    uint16_t id = 1;
    uint16_t sequence = 0;
    uint32_t src_ip = inet_addr("192.168.0.106");
    uint8_t src_mac[6] = {0x00, 0x0c, 0x29, 0x18, 0xc0, 0x11};
    uint8_t dest_mac[6] = {0xcc, 0x2d, 0x21, 0xb4, 0x19, 0xe0};
    uint8_t buffer[ETHERNET_FRAME_SIZE];
    uint8_t recvBuffer[ETHERNET_FRAME_SIZE];
    std::memset(buffer, 0, ETHERNET_FRAME_SIZE);
    std::memset(recvBuffer, 0, ETHERNET_FRAME_SIZE);

    IPHeader ip_header;
    ICMPHeader icmp_header;
    ICMP::createEchoRequest(icmp_header, id, sequence);
    IP::createIPHeader(ip_header, src_ip, dest_ip, IP_HEADER_SIZE + ICMP_HEADER_SIZE, IPPROTO_ICMP);

    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    std::memcpy(sa.sll_addr, dest_mac, 6);
    sa.sll_halen = 6;
    for (int i = 0; i < numPings; ++i)
    {
        icmp_header.sequence++;
        icmp_header.checksum = 0;
        std::memcpy(buffer + ETHERNET_HEADER_SIZE, &ip_header, IP_HEADER_SIZE);
        std::memcpy(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE, &icmp_header, ICMP_HEADER_SIZE);
        EthernetFrame icmp_frame(dest_mac, src_mac, 0x0800, buffer + ETHERNET_HEADER_SIZE, IP_HEADER_SIZE + ICMP_HEADER_SIZE);

        auto start = std::chrono::high_resolution_clock::now();
        if (sendto(sockfd, icmp_frame.getFrame(), icmp_frame.getFrameSize(), 0, (struct sockaddr *)&sa, sizeof(sa)) == -1)
        {
            perror("sendto");
            return;
        }
        sent++;
        ssize_t num_bytes = recvfrom(sockfd, recvBuffer, ETHERNET_FRAME_SIZE, 0, NULL, NULL);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        if (num_bytes == -1)
        {
            perror("recvfrom");
            return;
        }
        IPHeader *ip_header = reinterpret_cast<IPHeader *>(recvBuffer + ETHERNET_HEADER_SIZE);
        if (ip_header->protocol == IPPROTO_ICMP)
        {
            ICMPHeader *icmp_header = reinterpret_cast<ICMPHeader *>(recvBuffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
            std::cout << "来自 " << inet_ntoa(*(struct in_addr *)&dest_ip) << " 的回复: 字节=" << num_bytes << " 时间=" << duration << "ms TTL=" << (int)ip_header->ttl << std::endl;
        }
    }
}

void printTCPHeader(const TCPHeader &tcp_header)
{
    std::cout << "TCP Header:" << std::endl;
    std::cout << "    Source Port: " << ntohs(tcp_header.src_port) << std::endl;
    std::cout << "    Destination Port: " << ntohs(tcp_header.dest_port) << std::endl;
    std::cout << "    Sequence Number: " << ntohl(tcp_header.seq_num) << std::endl;
    std::cout << "    Acknowledgment Number: " << ntohl(tcp_header.ack_num) << std::endl;
    std::cout << "    Data Offset: " << (tcp_header.data_offset >> 4) << std::endl;
    std::cout << "    Flags: " << std::bitset<8>(tcp_header.flags) << std::endl;
    std::cout << "    Window Size: " << ntohs(tcp_header.window_size) << std::endl;
    std::cout << "    Checksum: " << ntohs(tcp_header.checksum) << std::endl;
    std::cout << "    Urgent Pointer: " << ntohs(tcp_header.urgent_ptr) << std::endl;
}

void printIPHeader(const IPHeader& ip_header) {
    std::cout << "IP Header:" << std::endl;
    std::cout << "    Version: " << ((ip_header.version_ihl >> 4) & 0xF) << std::endl;
    std::cout << "    IHL: " << (ip_header.version_ihl & 0xF) << std::endl;
    std::cout << "    Type of Service: " << (int)ip_header.tos << std::endl;
    std::cout << "    Total Length: " << ntohs(ip_header.total_length) << std::endl;
    std::cout << "    Identification: " << ntohs(ip_header.id) << std::endl;
    std::cout << "    Flags and Fragment Offset: " << ntohs(ip_header.flags_offset) << std::endl;
    std::cout << "    Time to Live: " << (int)ip_header.ttl << std::endl;
    std::cout << "    Protocol: " << (int)ip_header.protocol << std::endl;
    std::cout << "    Header Checksum: " << ntohs(ip_header.checksum) << std::endl;
    std::cout << "    Source IP: " << inet_ntoa(*(struct in_addr*)&ip_header.src_ip) << std::endl;
    std::cout << "    Destination IP: " << inet_ntoa(*(struct in_addr*)&ip_header.dest_ip) << std::endl;
}

bool NetworkInterface::sendTCPHandshake(uint32_t dest_ip, uint16_t dest_port)
{
    uint8_t dest_mac[6];
    if (!ARPCache::get_instance().get_Mac(dest_ip, dest_mac)) {
        if (!this->sendARPRequest(dest_ip, dest_mac) || !this->receiveARPReply(dest_ip, dest_mac)) {
            return false;
        }
    }

    uint8_t buffer[ETHERNET_FRAME_SIZE];
    std::memset(buffer, 0, ETHERNET_FRAME_SIZE);

    IPHeader ip_header;
    TCPHeader tcp_header;

    tcp_header.src_port = htons(12345); // 随机源端口
    tcp_header.dest_port = htons(dest_port);
    tcp_header.seq_num = htonl(0); // 初始序列号
    tcp_header.ack_num = 0;
    tcp_header.data_offset = (sizeof(TCPHeader) / 4) << 4;
    tcp_header.flags = TCPHeader::SYN;
    tcp_header.window_size = htons(65535);
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;

    IP::createIPHeader(ip_header, src_ip, dest_ip, IP_HEADER_SIZE + sizeof(TCPHeader), IPPROTO_TCP);

    std::memcpy(buffer + ETHERNET_HEADER_SIZE, &ip_header, IP_HEADER_SIZE);
    std::memcpy(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE, &tcp_header, sizeof(TCPHeader));

    EthernetFrame tcp_frame(dest_mac, src_mac, ETHER_TYPE_IP, buffer + ETHERNET_HEADER_SIZE, IP_HEADER_SIZE + sizeof(TCPHeader));

    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    std::memcpy(sa.sll_addr, dest_mac, 6); // 目的MAC地址需通过ARP获取
    sa.sll_halen = 6;

    std::cout << "[ TCP ] Sending SYN packet:" << std::endl;
    printTCPHeader(tcp_header);
    if (sendto(sockfd, tcp_frame.getFrame(), tcp_frame.getFrameSize(), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("sendto");
        return false;
    }
    std::cout << "[ TCP ] SYN packet sent to " << inet_ntoa(*(struct in_addr*)&dest_ip) << ":" << dest_port << std::endl;
    return true;
}

bool NetworkInterface::receiveTCPHandshake(uint32_t &seq_num, uint32_t &ack_num)
{
    uint8_t buffer[ETHERNET_FRAME_SIZE];
    fd_set read_fds;
    struct timeval timeout;

    while (true) {
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        int ret = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (ret == -1) {
            perror("select");
            return false;
        } else if (ret == 0) {
            std::cerr << "接收超时。" << std::endl;
            return false;
        }

        int num_bytes = recvfrom(sockfd, buffer, ETHERNET_FRAME_SIZE, 0, NULL, NULL);
        if (num_bytes == -1) {
            perror("recvfrom");
            return false;
        }

        IPHeader* ip_header = reinterpret_cast<IPHeader*>(buffer + ETHERNET_HEADER_SIZE);
        uint16_t ethertype = ntohs(*(uint16_t*)(buffer + 12));

        std::cout << "[ Debug ] Received Ethernet frame, EtherType: " << std::hex << ethertype << std::dec << ", Length: " << num_bytes << std::endl;

        if (ethertype == ETHER_TYPE_IP && ip_header->protocol == IPPROTO_TCP) {
            std::cout << "[ TCP ] Received TCP packet from " << inet_ntoa(*(struct in_addr*)&ip_header->src_ip) << std::endl;
            printIPHeader(*ip_header);
            TCPHeader* tcp_header = reinterpret_cast<TCPHeader*>(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
            std::cout << "[ TCP ] TCP flags: " << std::bitset<8>(tcp_header->flags) << std::endl;
            printTCPHeader(*tcp_header);

            if ((tcp_header->flags & TCPHeader::SYN) && (tcp_header->flags & TCPHeader::ACK)) {
                seq_num = ntohl(tcp_header->seq_num);
                ack_num = ntohl(tcp_header->ack_num);
                std::cout << "[ TCP ] SYN-ACK packet received:" << std::endl;
                printTCPHeader(*tcp_header);
                return true;
            } else {
                std::cout << "[ TCP ] Unexpected TCP flags: " << std::bitset<8>(tcp_header->flags) << std::endl;
            }
        } else {
            std::cout << "[ TCP ] Received non-TCP packet" << std::endl;
        }
    }

    return false;
}

bool NetworkInterface::sendTCPAck(uint32_t dest_ip, uint16_t dest_port, uint32_t seq_num, uint32_t ack_num)
{
    uint8_t dest_mac[6];
    if (!ARPCache::get_instance().get_Mac(dest_ip, dest_mac)) {
        if (!this->sendARPRequest(dest_ip, dest_mac) || !this->receiveARPReply(dest_ip, dest_mac)) {
            return false;
        }
    }

    uint8_t buffer[ETHERNET_FRAME_SIZE];
    std::memset(buffer, 0, ETHERNET_FRAME_SIZE);

    IPHeader ip_header;
    TCPHeader tcp_header;

    tcp_header.src_port = htons(12345); // 随机源端口
    tcp_header.dest_port = htons(dest_port);
    tcp_header.seq_num = htonl(seq_num);
    tcp_header.ack_num = htonl(ack_num);
    tcp_header.data_offset = (sizeof(TCPHeader) / 4) << 4;
    tcp_header.flags = TCPHeader::ACK;
    tcp_header.window_size = htons(65535);
    tcp_header.checksum = 0;
    tcp_header.urgent_ptr = 0;

    IP::createIPHeader(ip_header, src_ip, dest_ip, IP_HEADER_SIZE + sizeof(TCPHeader), IPPROTO_TCP);

    std::memcpy(buffer + ETHERNET_HEADER_SIZE, &ip_header, IP_HEADER_SIZE);
    std::memcpy(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE, &tcp_header, sizeof(TCPHeader));

    EthernetFrame tcp_frame(dest_mac, src_mac, ETHER_TYPE_IP, buffer + ETHERNET_HEADER_SIZE, IP_HEADER_SIZE + sizeof(TCPHeader));

    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    std::memcpy(sa.sll_addr, dest_mac, 6); // 目的MAC地址需通过ARP获取
    sa.sll_halen = 6;

    std::cout << "[ TCP ] Sending ACK packet:" << std::endl;
    printTCPHeader(tcp_header);
    if (sendto(sockfd, tcp_frame.getFrame(), tcp_frame.getFrameSize(), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("sendto");
        return false;
    }
    std::cout << "[ TCP ] ACK packet sent to " << inet_ntoa(*(struct in_addr*)&dest_ip) << ":" << dest_port << std::endl;
    return true;
}

bool NetworkInterface::sendUDPMessage(uint32_t dest_ip, uint16_t dest_port, const std::string &message)
{
    uint8_t dest_mac[6];
    if (!ARPCache::get_instance().get_Mac(dest_ip, dest_mac)) {
        if (!this->sendARPRequest(dest_ip, dest_mac) || !this->receiveARPReply(dest_ip, dest_mac)) {
            return false;
        }
    }

    uint8_t buffer[ETHERNET_FRAME_SIZE];
    std::memset(buffer, 0, ETHERNET_FRAME_SIZE);

    IPHeader ip_header;
    UDPHeader udp_header;

    udp_header.src_port = htons(12345); // 随机源端口
    udp_header.dest_port = htons(dest_port);
    udp_header.length = htons(sizeof(UDPHeader) + message.size());
    udp_header.checksum = 0; // 校验和暂时为0

    IP::createIPHeader(ip_header, src_ip, dest_ip, IP_HEADER_SIZE + sizeof(UDPHeader) + message.size(), IPPROTO_UDP);

    std::memcpy(buffer + ETHERNET_HEADER_SIZE, &ip_header, IP_HEADER_SIZE);
    std::memcpy(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE, &udp_header, sizeof(UDPHeader));
    std::memcpy(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + sizeof(UDPHeader), message.c_str(), message.size());

    EthernetFrame udp_frame(dest_mac, src_mac, ETHER_TYPE_IP, buffer + ETHERNET_HEADER_SIZE, IP_HEADER_SIZE + sizeof(UDPHeader) + message.size());

    struct sockaddr_ll sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    std::memcpy(sa.sll_addr, dest_mac, 6); // 目的MAC地址需通过ARP获取
    sa.sll_halen = 6;

    if (sendto(sockfd, udp_frame.getFrame(), udp_frame.getFrameSize(), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("sendto");
        return false;
    }
    std::cout << "[ UDP ] Message sent to " << inet_ntoa(*(struct in_addr*)&dest_ip) << ":" << dest_port << std::endl;
    return true;
}

bool NetworkInterface::receiveUDPMessage(uint32_t &src_ip, uint16_t &src_port, std::string &message)
{
    uint8_t buffer[ETHERNET_FRAME_SIZE];
    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ret = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (ret == -1) {
        perror("select");
        return false;
    } else if (ret == 0) {
        std::cerr << "接收超时。" << std::endl;
        return false;
    }

    int num_bytes = recvfrom(sockfd, buffer, ETHERNET_FRAME_SIZE, 0, NULL, NULL);
    if (num_bytes == -1) {
        perror("recvfrom");
        return false;
    }

    IPHeader* ip_header = reinterpret_cast<IPHeader*>(buffer + ETHERNET_HEADER_SIZE);
    if (ip_header->protocol == IPPROTO_UDP) {
        UDPHeader* udp_header = reinterpret_cast<UDPHeader*>(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
        src_ip = ip_header->src_ip;
        src_port = ntohs(udp_header->src_port);
        int udp_data_len = ntohs(udp_header->length) - sizeof(UDPHeader);
        message.assign(reinterpret_cast<char*>(buffer + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + sizeof(UDPHeader)), udp_data_len);
        std::cout << "[ UDP ] Message received from " << inet_ntoa(*(struct in_addr*)&src_ip) << ":" << src_port << std::endl;
        return true;
    }

    return false;
}
