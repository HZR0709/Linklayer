#ifndef DNSMESSAGE_H
#define DNSMESSAGE_H

#include <cstdint>
#include <vector>
#include <string>

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct DNSQuestion {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;
};

struct DNSAnswer {
    std::string name;
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t rdlength;
    std::vector<uint8_t> rdata;
};

class DNSMessage {
public:
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<DNSAnswer> answers;

    DNSMessage();
    std::vector<uint8_t> encode();
    static DNSMessage decode(const std::vector<uint8_t>& data);
    static std::string decodeDomainName(const std::vector<uint8_t>& data, size_t& offset);
    static std::vector<uint8_t> encodeDomainName(const std::string& domain);
};

#endif // DNSMESSAGE_H
