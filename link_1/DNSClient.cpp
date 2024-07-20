#include "DNSClient.h"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

bool DNSClient::resolve(const std::string& domain, std::string& ip) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &servaddr.sin_addr);

    DNSMessage message;
    message.header.id = htons(1234); // random ID
    message.header.flags = htons(0x0100); // standard query
    message.header.qdcount = htons(1); // one question

    DNSQuestion question;
    question.qname = domain;
    question.qtype = 1; // A record
    question.qclass = 1; // IN
    message.questions.push_back(question);

    auto data = message.encode();
    if (sendto(sockfd, data.data(), data.size(), 0, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto");
        close(sockfd);
        return false;
    }

    std::cout << "Sent DNS query for domain: " << domain << std::endl;

    std::vector<uint8_t> buffer(512);
    socklen_t len = sizeof(servaddr);
    int n = recvfrom(sockfd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&servaddr, &len);
    if (n < 0) {
        perror("recvfrom");
        close(sockfd);
        return false;
    }

    std::cout << "Received DNS response, length: " << n << " bytes" << std::endl;

    close(sockfd);

    auto response = DNSMessage::decode(buffer);
    std::cout << "Decoded DNS response, ANCOUNT: " << ntohs(response.header.ancount) << std::endl;

    if (ntohs(response.header.ancount) > 0) {
        for (const auto& answer : response.answers) {
            std::cout << "Answer type: " << answer.type << ", class: " << answer._class << std::endl;
            if (answer.type == 1 && answer._class == 1) { // A record
                ip = inet_ntoa(*(struct in_addr*)answer.rdata.data());
                return true;
            }
        }
    }

    return false;
}
