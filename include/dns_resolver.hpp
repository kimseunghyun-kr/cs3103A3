// ===================== include/dns_resolver.hpp =====================
#pragma once
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

namespace geo
{
    struct ResolvedAddress
    {
        int family;
        int socktype;
        int protocol;
        sockaddr_storage addr;
        socklen_t addrlen;
    };

    class DNSResolver
    {
    public:
        static std::vector<ResolvedAddress> resolve(const std::string &host, int port);
    };
} // namespace geo