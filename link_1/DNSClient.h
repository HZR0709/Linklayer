#ifndef DNSCLIENT_H
#define DNSCLIENT_H

#include "DNSMessage.h"
#include <string>

class DNSClient {
public:
    static bool resolve(const std::string& domain, std::string& ip);
};

#endif // DNSCLIENT_H
