#include "tcp_probe_common.hpp"
#include "diag_logger.hpp"
#include "utils_net.hpp"
#include "net_compat.hpp"

#include <array>
#include <unordered_map>
#include <chrono>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <vector>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace geo {

// RAW: craft IP+TCP SYN by hand, because well.. life.. apparently.
std::vector<uint16_t> send_raw_probes(
    int raw_send_sock,
    const sockaddr_in &dst,
    const in_addr &src_ip,
    const in_addr &dst_ip,
    int port,
    int ttl,
    DiagLogger *diag,
    std::unordered_map<uint16_t, ProbeState> &in_flight)
{
    using clk = std::chrono::steady_clock;
    std::vector<uint16_t> sports;

    for (int i = 0; i < 3; ++i) {
        uint16_t sport = static_cast<uint16_t>(33434 + ttl * 3 + i);
        sports.push_back(sport);

        // minimal IP+TCP SYN
        std::array<uint8_t, sizeof(iphdr) + sizeof(tcphdr)> pkt{};
        auto *ip = reinterpret_cast<iphdr *>(pkt.data());
        auto *tcp = reinterpret_cast<tcphdr *>(pkt.data() + sizeof(iphdr));

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(pkt.size());
        ip->id = htons(static_cast<uint16_t>((ttl << 8) | i));
        ip->frag_off = 0;
        ip->ttl = static_cast<uint8_t>(ttl);
        ip->protocol = IPPROTO_TCP;
        ip->saddr = src_ip.s_addr;
        ip->daddr = dst_ip.s_addr;
        ip->check = 0;

        std::memset(tcp, 0, sizeof(tcphdr));
        tcp->source = htons(sport);
        tcp->dest   = htons(static_cast<uint16_t>(port));
        tcp->seq    = htonl((ttl << 24) | (i << 16) | 0x1234);
        tcp->doff   = 5;
        TCP_SET_SYN(tcp, 1);
        tcp->window = htons(65535);

        // compute checksums (because NICs won’t babysit us anymore)
        ip->check = geo::net::ip_checksum(ip);
        tcp->check = geo::net::tcp_checksum(ip, tcp, sizeof(tcphdr));

        in_flight[sport] = ProbeState{ttl, clk::now()};

        ssize_t rc = ::sendto(raw_send_sock, pkt.data(), pkt.size(), 0,
                              reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));

        if (diag) {
            if (rc < 0)
                diag->log("PROBE_SEND_ERR mode=raw ttl=" + std::to_string(ttl) +
                          " idx=" + std::to_string(i) + " sport=" + std::to_string(sport) +
                          " errno=" + std::to_string(errno) + " (" + std::strerror(errno) + ")");
            else
                diag->log("PROBE_SENT mode=raw ttl=" + std::to_string(ttl) +
                          " idx=" + std::to_string(i) + " sport=" + std::to_string(sport) +
                          " bytes=" + std::to_string(rc));
        }
    }
    return sports;
}

} // namespace geo
