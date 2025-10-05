#include "tcp_probe_common.hpp"
#include "diag_logger.hpp"
#include <unordered_map>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

namespace geo {

// CONNECT: kernel builds packet; we just twiddle TTL and pray NAT cooperates.
std::unordered_map<uint16_t,int> send_connect_probes(
    const sockaddr_in &dst,
    const in_addr &src_ip,
    int ttl,
    DiagLogger *diag,
    std::unordered_map<uint16_t, ProbeState> &in_flight)
{
    using clk = std::chrono::steady_clock;
    std::unordered_map<uint16_t,int> probe_socks;

    for (int i = 0; i < 3; ++i) {
        uint16_t sport = static_cast<uint16_t>(33434 + ttl * 3 + i);

        int s = ::socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            if (diag) diag->log("WARN socket() failed");
            continue;
        }

        sockaddr_in src{};
        src.sin_family = AF_INET;
        src.sin_port = htons(sport);
        src.sin_addr = src_ip;
        (void)::bind(s, reinterpret_cast<sockaddr *>(&src), sizeof(src));

        int ttl_val = ttl;
        (void)::setsockopt(s, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));

        int flags = ::fcntl(s, F_GETFL, 0);
        if (flags != -1)
            ::fcntl(s, F_SETFL, flags | O_NONBLOCK);

        in_flight[sport] = ProbeState{ttl, clk::now()};
        (void)::connect(s, reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
        probe_socks[sport] = s;

        if (diag)
            diag->log("PROBE_SENT mode=connect ttl=" + std::to_string(ttl) +
                      " idx=" + std::to_string(i) + " sport=" + std::to_string(sport));
    }
    return probe_socks;
}

} // namespace geo
