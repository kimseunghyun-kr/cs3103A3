#include "tcp_probe_common.hpp"
#include "dns_resolver.hpp"
#include <unistd.h>
#include <arpa/inet.h>
#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>
#include <unordered_map>

namespace geo {

using clk = std::chrono::steady_clock;

// ------------------------------------------
// Common structs
// ------------------------------------------
ProbeState::ProbeState(int t, clk::time_point tp) : ttl(t), t0(tp), done(false) {}

// Utility for per-hop stats aggregation
HopAgg::HopAgg() : count(0), min_ms(0), max_ms(0), sum_ms(0), reached(false) {}

// Pick first IPv4 from resolver
in_addr pick_ipv4(const std::vector<ResolvedAddress> &addrs) {
    for (const auto &ra : addrs)
        if (ra.family == AF_INET)
            return reinterpret_cast<const sockaddr_in *>(&ra.addr)->sin_addr;
    throw std::runtime_error("Destination has no IPv4 address");
}

// Figure out local IPv4 used to reach given destination
in_addr find_local_ipv4_to(const in_addr &dst) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        throw std::runtime_error("socket(AF_INET,SOCK_DGRAM) failed");

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(53);
    to.sin_addr = dst;
    (void)::connect(s, reinterpret_cast<sockaddr *>(&to), sizeof(to));

    sockaddr_in me{};
    socklen_t len = sizeof(me);
    if (::getsockname(s, reinterpret_cast<sockaddr *>(&me), &len) < 0) {
        ::close(s);
        throw std::runtime_error("getsockname failed");
    }
    ::close(s);
    return me.sin_addr;
}

std::string ip_to_string(uint32_t be_ip) {
    in_addr a;
    a.s_addr = be_ip;
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? std::string(buf) : std::string();
}

} // namespace geo
