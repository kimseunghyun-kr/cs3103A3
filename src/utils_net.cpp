#include "utils_net.hpp"
#include <vector>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h> // htons

namespace geo::net {

uint16_t csum16(const void* data, std::size_t len) {
    const uint16_t* p = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t ip_checksum(const iphdr* ip) {
    return csum16(ip, ip->ihl * 4);
}

uint16_t tcp_checksum(const iphdr* ip, const tcphdr* tcp, std::size_t tcplen)
{
    struct Pseudo {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } ph { ip->saddr, ip->daddr, 0, IPPROTO_TCP,
           htons(static_cast<uint16_t>(tcplen)) };

    if (tcplen > 65535)
        throw std::runtime_error("invalid TCP length for checksum");

    std::vector<uint8_t> buf(sizeof(Pseudo) + tcplen);

    std::memcpy(static_cast<void*>(buf.data()), &ph, sizeof(Pseudo));
    std::memcpy(static_cast<void*>(buf.data() + sizeof(Pseudo)),
                static_cast<const void*>(tcp),
                tcplen);

    return csum16(buf.data(), buf.size());
}


} // namespace geo::net
