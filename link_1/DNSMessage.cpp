#include "DNSMessage.h"
#include <cstring>
#include <arpa/inet.h>
#include <iostream>

DNSMessage::DNSMessage() {
    memset(&header, 0, sizeof(header));
}

std::vector<uint8_t> DNSMessage::encode() {
    std::vector<uint8_t> data;
    data.resize(sizeof(DNSHeader));
    memcpy(data.data(), &header, sizeof(DNSHeader));

    for (const auto& question : questions) {
        auto qname = encodeDomainName(question.qname);
        data.insert(data.end(), qname.begin(), qname.end());
        uint16_t qtype = htons(question.qtype);
        uint16_t qclass = htons(question.qclass);
        data.insert(data.end(), (uint8_t*)&qtype, (uint8_t*)&qtype + sizeof(qtype));
        data.insert(data.end(), (uint8_t*)&qclass, (uint8_t*)&qclass + sizeof(qclass));
    }
    return data;
}

DNSMessage DNSMessage::decode(const std::vector<uint8_t>& data) {
    DNSMessage message;
    size_t offset = 0;
    memcpy(&message.header, data.data(), sizeof(DNSHeader));
    offset += sizeof(DNSHeader);

    std::cout << "DNS Header ID: " << ntohs(message.header.id) << std::endl;
    std::cout << "Flags: " << std::hex << ntohs(message.header.flags) << std::dec << std::endl;
    std::cout << "QDCOUNT: " << ntohs(message.header.qdcount) << ", ANCOUNT: " << ntohs(message.header.ancount) << std::endl;

    for (int i = 0; i < ntohs(message.header.qdcount); ++i) {
        DNSQuestion question;
        question.qname = decodeDomainName(data, offset);
        question.qtype = ntohs(*(uint16_t*)(data.data() + offset));
        offset += sizeof(uint16_t);
        question.qclass = ntohs(*(uint16_t*)(data.data() + offset));
        offset += sizeof(uint16_t);
        message.questions.push_back(question);
    }

    for (int i = 0; i < ntohs(message.header.ancount); ++i) {
        DNSAnswer answer;
        answer.name = decodeDomainName(data, offset);
        answer.type = ntohs(*(uint16_t*)(data.data() + offset));
        offset += sizeof(uint16_t);
        answer._class = ntohs(*(uint16_t*)(data.data() + offset));
        offset += sizeof(uint16_t);
        answer.ttl = ntohl(*(uint32_t*)(data.data() + offset));
        offset += sizeof(uint32_t);
        answer.rdlength = ntohs(*(uint16_t*)(data.data() + offset));
        offset += sizeof(uint16_t);
        answer.rdata.insert(answer.rdata.end(), data.begin() + offset, data.begin() + offset + answer.rdlength);
        offset += answer.rdlength;
        message.answers.push_back(answer);

        std::cout << "Decoded Answer " << i+1 << ": " << std::endl;
        std::cout << "  Name: " << answer.name << std::endl;
        std::cout << "  Type: " << answer.type << std::endl;
        std::cout << "  Class: " << answer._class << std::endl;
        std::cout << "  TTL: " << answer.ttl << std::endl;
        std::cout << "  RDLength: " << answer.rdlength << std::endl;
        std::cout << "  RData: ";
        for (const auto& byte : answer.rdata) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    return message;
}

std::string DNSMessage::decodeDomainName(const std::vector<uint8_t>& data, size_t& offset) {
    std::string domain;
    while (data[offset] != 0) {
        if ((data[offset] & 0xC0) == 0xC0) { // 检查是否为指针
            uint16_t pointer = ((data[offset] & 0x3F) << 8) | data[offset + 1];
            size_t original_offset = offset + 2;
            offset = pointer;
            std::string result = decodeDomainName(data, offset);
            offset = original_offset;
            return result;
        }
        if (!domain.empty()) {
            domain += ".";
        }
        uint8_t length = data[offset++];
        domain.append(data.begin() + offset, data.begin() + offset + length);
        offset += length;
    }
    ++offset;
    return domain;
}

std::vector<uint8_t> DNSMessage::encodeDomainName(const std::string& domain) {
    std::vector<uint8_t> encoded;
    size_t start = 0, end;
    while ((end = domain.find('.', start)) != std::string::npos) {
        encoded.push_back(end - start);
        encoded.insert(encoded.end(), domain.begin() + start, domain.begin() + end);
        start = end + 1;
    }
    encoded.push_back(domain.size() - start);
    encoded.insert(encoded.end(), domain.begin() + start, domain.end());
    encoded.push_back(0);
    return encoded;
}
