// ===================== File: include/tcp_probe.hpp =====================
#pragma once
#include <string>
#include <vector>
#include "diag_logger.hpp"

namespace geo {

    struct ProbeHopSummary {
        int ttl{};
        std::string hop_ip;
        int num_replies{};
        double rtt_min_ms{};
        double rtt_avg_ms{};
        double rtt_max_ms{};
        bool reached{};
    };

    enum class SendMode { Auto, Connect, Raw };

    class TcpProbe {
    public:
        static std::vector<ProbeHopSummary>
        trace(const std::string& host, int port, int max_hops = 30, int timeout_ms = 1000,
              SendMode mode = SendMode::Auto,
              DiagLogger* diag = nullptr);
    };

} // namespace geo
