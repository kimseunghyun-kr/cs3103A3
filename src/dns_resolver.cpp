// ===================== src/dns_resolver.cpp =====================
#include "dns_resolver.hpp"
#include <cstring>
#include <stdexcept>

namespace geo
{
    std::vector<ResolvedAddress> DNSResolver::resolve(const std::string &host, int port)
    {
        std::vector<ResolvedAddress> results;

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo *res = nullptr;

        const std::string portStr = std::to_string(port);
        int status = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
        if (status != 0)
        {
            throw std::runtime_error(std::string("DNS resolution failed for ") + host + ": " + gai_strerror(status));
        }

        for (auto *p = res; p != nullptr; p = p->ai_next)
        {
            ResolvedAddress ra{};
            ra.family = p->ai_family;
            ra.socktype = p->ai_socktype;
            ra.protocol = p->ai_protocol;
            ra.addrlen = static_cast<socklen_t>(p->ai_addrlen);
            std::memcpy(&ra.addr, p->ai_addr, p->ai_addrlen);
            results.push_back(ra);
        }
        freeaddrinfo(res);
        return results;
    }
} // namespace geo