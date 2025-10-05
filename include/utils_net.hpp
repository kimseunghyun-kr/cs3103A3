#pragma once
#include <cstddef>
#include <cstdint>
#include "net_compat.hpp"   // iphdr
#include <netinet/tcp.h>  // tcphdr

namespace geo::net {

// Internet checksum over an arbitrary buffer
uint16_t csum16(const void* data, std::size_t len);

// IPv4 header checksum (covers only the IP header)
uint16_t ip_checksum(const iphdr* ip);

// TCP checksum (covers TCP header+payload using IPv4 pseudo-header)
// tcplen = sizeof(tcphdr) + payload_len (+ options if present)
uint16_t tcp_checksum(const iphdr* ip, const tcphdr* tcp, std::size_t tcplen);

} // namespace geo::net
