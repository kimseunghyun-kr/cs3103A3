

// ===================== include/tcp_probe.hpp =====================
#pragma once
#include <string>
#include <vector>


namespace geo {
struct ProbeHopSummary {
int ttl{};
std::string hop_ip; // responder IP (first seen), or empty if none
int num_replies{}; // out of 3
double rtt_min_ms{};
double rtt_avg_ms{};
double rtt_max_ms{};
bool reached{}; // true if this hop is the destination (RST or SYN+ACK)
};


class TcpProbe {
public:
// Sends 3 TCP SYN probes per hop with TTL=1..max_hops, waits up to timeout_ms per hop.
// Requires CAP_NET_RAW or root. IPv4 only.
static std::vector<ProbeHopSummary> trace(const std::string& host, int port,
int max_hops = 30, int timeout_ms = 1000);
};
} // namespace geo