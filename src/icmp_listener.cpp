//// ===================== File: src/icmp_listener.cpp =====================
#include "icmp_listener.hpp"

#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace geo
{

    bool IcmpListener::open()
    {
        if (fd_ != -1)
            return true;
        fd_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        return fd_ >= 0;
    }

    void IcmpListener::close()
    {
        if (fd_ != -1)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    std::optional<IcmpListener::TimeExceeded> IcmpListener::recv_time_exceeded()
    {
        std::array<uint8_t, 2048> buf{};
        sockaddr_in from{};
        socklen_t flen = sizeof(from);
        ssize_t n = ::recvfrom(fd_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr *>(&from), &flen);
        if (n <= 0)
            return std::nullopt;

        auto *ip_outer = reinterpret_cast<iphdr *>(buf.data());
        size_t off = ip_outer->ihl * 4;
        if (off + sizeof(icmphdr) > static_cast<size_t>(n))
            return std::nullopt;
        auto *icmp = reinterpret_cast<icmphdr *>(buf.data() + off);
        if (icmp->type != ICMP_TIME_EXCEEDED)
            return std::nullopt;

        size_t inner_off = off + sizeof(icmphdr);
        if (inner_off + sizeof(iphdr) + 8 > static_cast<size_t>(n))
            return std::nullopt;
        auto *ip_inner = reinterpret_cast<iphdr *>(buf.data() + inner_off);
        size_t tcp_off = inner_off + ip_inner->ihl * 4;
        if (tcp_off + 8 > static_cast<size_t>(n))
            return std::nullopt;

        uint16_t sport = ntohs(*reinterpret_cast<uint16_t *>(buf.data() + tcp_off + 0));
        // uint16_t dport = ntohs(*reinterpret_cast<uint16_t*>(buf.data() + tcp_off + 2));

        char ipbuf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &ip_outer->saddr, ipbuf, sizeof(ipbuf)))
            return std::nullopt;

        TimeExceeded te{};
        te.from_ip = ipbuf;
        te.orig_sport = sport;
        te.orig_ttl = ip_inner->ttl;
        return te;
    }

} // namespace geo
