#pragma once

#include "dns_resolver.hpp"

#include <chrono>
#include <string>
#include <vector>
#include <netinet/in.h>

namespace geo {

using clk = std::chrono::steady_clock;

// ProbeState: tracks per-probe TTL + send time
struct ProbeState {
    int ttl;
    clk::time_point t0;
    bool done = false;
    ProbeState() = default;
    ProbeState(int t, clk::time_point tp);
};

// HopAgg: aggregate stats for one hop
struct HopAgg {
    std::string ip;
    int count;
    double min_ms, max_ms, sum_ms;
    bool reached;
    HopAgg();
};

// helpers shared across files
in_addr pick_ipv4(const std::vector<ResolvedAddress>& addrs);
in_addr find_local_ipv4_to(const in_addr& dst);
std::string ip_to_string(uint32_t be_ip);

} // namespace geo
