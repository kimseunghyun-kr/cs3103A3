// ===================== File: src/tcp_probe.cpp =====================
// This file used to do *everything*. Now it just orchestrates.
// Raw/Connect sending paths are refactored into their own files
// because nobody likes 1000-line monoliths.

#include "tcp_probe.hpp"
#include "dns_resolver.hpp"
#include "icmp_listener.hpp"
#include "utils_net.hpp"
#include "net_compat.hpp"
#include "tcp_probe_common.hpp"


#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace geo
{
// forward declarations (now in other cpp files)
std::vector<uint16_t> send_raw_probes(
    int raw_send_sock, const sockaddr_in &dst,
    const in_addr &src_ip, const in_addr &dst_ip,
    int port, int ttl, DiagLogger *diag,
    std::unordered_map<uint16_t, ProbeState> &in_flight);

std::unordered_map<uint16_t,int> send_connect_probes(
    const sockaddr_in &dst, const in_addr &src_ip, int ttl, DiagLogger *diag,
    std::unordered_map<uint16_t, ProbeState> &in_flight);

// ===================================================================
// TcpProbe::trace
// Main driver. Sends 3 probes per TTL until dest reached or max_hops.
// ===================================================================
std::vector<ProbeHopSummary>
TcpProbe::trace(const std::string &host, int port, int max_hops, int timeout_ms,
                SendMode mode, DiagLogger *diag)
{
    // --- resolve destination
    auto addrs = DNSResolver::resolve(host, port);
    in_addr dst_ip = pick_ipv4(addrs);
    in_addr src_ip = find_local_ipv4_to(dst_ip);

    if (diag)
    {
        char dbuf[INET_ADDRSTRLEN], sbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dst_ip, dbuf, sizeof(dbuf));
        inet_ntop(AF_INET, &src_ip, sbuf, sizeof(sbuf));
        diag->log(std::string("SETUP src=") + sbuf + " dst=" + dbuf + ":" + std::to_string(port) +
                  " mode=" + (mode == SendMode::Raw ? "raw" :
                              mode == SendMode::Connect ? "connect" : "auto"));
    }

    // --- ICMP receiver
    IcmpListener icmp;
    bool ok = false;
    switch (mode)
    {
    case SendMode::Raw:
        ok = icmp.open(IcmpListener::OpenMode::RawOnly);
        break;

    // I HATE THE STUPID NIC ISSUE FFS I BOUGHT A ACTUAL NIC TO DEBUG THIS CRAP,
    // spent 50 bucks to get the NIC to not use this route. still stuck here.
    case SendMode::Connect:
        ok = icmp.open(IcmpListener::OpenMode::DatagramOnly);
        break;

    case SendMode::Auto:
        ok = icmp.open(IcmpListener::OpenMode::Auto);
        break;
    }

    // ffs debugging this is insane
    if (!ok)
        throw std::runtime_error("Failed to open ICMP socket (need CAP_NET_RAW/root)");

    // --- TCP raw recv socket (for RST/SYNACK)
    int tcp_recv_sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (tcp_recv_sock < 0)
        throw std::runtime_error("Need CAP_NET_RAW/root to sniff TCP");

    int raw_send_sock = -1;

    // this should be default but NAT ate my ICMP logs.
    if (mode == SendMode::Raw)
    {
        raw_send_sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (raw_send_sock < 0)
            throw std::runtime_error("raw send socket failed");
        int on = 1;
        (void)setsockopt(raw_send_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    }

    // ----------------------------------------------------
    // main probing sequence
    // ----------------------------------------------------
    std::vector<ProbeHopSummary> out;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr = dst_ip;

    std::unordered_map<uint16_t, ProbeState> in_flight; // key: source port
    bool destination_reached = false;

    for (int ttl = 1; ttl <= max_hops && !destination_reached; ++ttl)
    {
        in_flight.clear();
        HopAgg agg{};
        if (diag)
            diag->log("HOP " + std::to_string(ttl) + ": send 3 probes");

        // ----------------------------------------------------
        // send probes (refactored out of this god-function)
        // ----------------------------------------------------
        std::unordered_map<uint16_t,int> probe_socks;
        if (mode == SendMode::Raw)
            send_raw_probes(raw_send_sock, dst, src_ip, dst_ip, port, ttl, diag, in_flight);
        else
            probe_socks = send_connect_probes(dst, src_ip, ttl, diag, in_flight);

        // ----------------------------------------------------
        // wait for replies (ICMP TimeExceeded or TCP replies)
        // ----------------------------------------------------
        using clk = std::chrono::steady_clock;
        auto deadline = clk::now() + std::chrono::milliseconds(timeout_ms);
        int replies_seen = 0;

        // --- hot loop; should be event-driven but life’s too short
        while (clk::now() < deadline && replies_seen < 3)
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            int maxfd = -1;
            FD_SET(icmp.fd(), &rfds);
            maxfd = std::max(maxfd, icmp.fd());
            FD_SET(tcp_recv_sock, &rfds);
            maxfd = std::max(maxfd, tcp_recv_sock);

            auto now = clk::now();
            auto remain = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            if (remain.count() < 0)
                break;
            timeval tv{static_cast<long>(remain.count() / 1000),
                       static_cast<suseconds_t>((remain.count() % 1000) * 1000)};

            int rc = ::select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
            if (rc <= 0)
                continue;

            // ICMP Time Exceeded (routers)
            if (FD_ISSET(icmp.fd(), &rfds))
            {
                if (auto te = icmp.recv_time_exceeded())
                {
                    auto it = in_flight.find(te->orig_sport);
                    if (it != in_flight.end() && !it->second.done)
                    {
                        double rtt = std::chrono::duration<double, std::milli>(
                                         clk::now() - it->second.t0).count();
                        if (agg.count == 0)
                            agg.ip = te->from_ip;
                        agg.count++;
                        if (agg.count == 1)
                            agg.min_ms = agg.max_ms = rtt;
                        else
                        {
                            agg.min_ms = std::min(agg.min_ms, rtt);
                            agg.max_ms = std::max(agg.max_ms, rtt);
                        }
                        agg.sum_ms += rtt;
                        it->second.done = true;
                        replies_seen++;

                        // 2025-10-05 diagnostics added: hope it logs something useful.
                        if (diag)
                            diag->log("ICMP_TIME_EXCEEDED from=" + te->from_ip +
                                      " sport=" + std::to_string(te->orig_sport) +
                                      " inner_ttl=" + std::to_string(te->orig_ttl) +
                                      " rtt_ms=" + std::to_string(rtt));
                    }
                    else
                    {
                        if (diag)
                            diag->log("ICMP_TIME_EXCEEDED (unmatched) sport=" +
                                      std::to_string(te->orig_sport));
                    }
                }
            }

            // Destination reached (TCP RST or SYN+ACK)
            if (FD_ISSET(tcp_recv_sock, &rfds))
            {
                std::array<uint8_t, 2048> buf{};
                sockaddr_in from{};
                socklen_t flen = sizeof(from);
                ssize_t n = ::recvfrom(tcp_recv_sock, buf.data(), buf.size(), 0,
                                       reinterpret_cast<sockaddr *>(&from), &flen);
                if (n > 0)
                {
                    auto *ip = reinterpret_cast<iphdr *>(buf.data());
                    size_t off = ip->ihl * 4;
                    if (off + sizeof(tcphdr) <= static_cast<size_t>(n))
                    {
                        auto *tcp = reinterpret_cast<tcphdr *>(buf.data() + off);
                        uint16_t dport = ntohs(tcp->dest);
                        auto it = in_flight.find(dport);
                        if (it != in_flight.end() && !it->second.done &&
                            ip->saddr == dst_ip.s_addr)
                        {
                            bool synack = (TCP_IS_SYN(tcp) && TCP_IS_ACK(tcp));
                            bool rst = TCP_IS_RST(tcp);
                            if (synack || rst)
                            {
                                double rtt = std::chrono::duration<double, std::milli>(
                                                 clk::now() - it->second.t0).count();
                                std::string hop_ip = ip_to_string(ip->saddr);
                                if (agg.count == 0)
                                    agg.ip = hop_ip;
                                agg.count++;
                                if (agg.count == 1)
                                    agg.min_ms = agg.max_ms = rtt;
                                else
                                {
                                    agg.min_ms = std::min(agg.min_ms, rtt);
                                    agg.max_ms = std::max(agg.max_ms, rtt);
                                }
                                agg.sum_ms += rtt;
                                agg.reached = true;
                                it->second.done = true;
                                replies_seen++;

                                if (diag)
                                    diag->log(std::string("DEST_REPLY type=") +
                                              (synack ? "SYN-ACK" : "RST") +
                                              " sport=" + std::to_string(dport) +
                                              " rtt_ms=" + std::to_string(rtt));

                                // yeah, we made it. break after summary.
                                destination_reached = true;
                            }
                        }
                    }
                }
            }
        }

        // close per-probe sockets (Connect/Auto)
        for (auto &kv : probe_socks)
            if (kv.second >= 0)
                ::close(kv.second);

        // --- summarize hop
        if (diag)
        {
            diag->log("HOP_SUMMARY ttl=" + std::to_string(ttl) +
                      " replies=" + std::to_string(agg.count) +
                      " reached=" + std::to_string(agg.reached ? 1 : 0));
            if (agg.count == 0)
                diag->log("NO_ICMP_THIS_HOP ttl=" + std::to_string(ttl) + " (timeout)");
        }

        ProbeHopSummary row{};
        row.ttl = ttl;
        row.reached = agg.reached;
        row.num_replies = agg.count;
        if (agg.count > 0)
        {
            row.hop_ip = agg.ip;
            row.rtt_min_ms = agg.min_ms;
            row.rtt_max_ms = agg.max_ms;
            row.rtt_avg_ms = agg.sum_ms / agg.count;
        }
        out.push_back(row);

        if (destination_reached)
        {
            if (diag)
                diag->log("STOP: destination reached at ttl=" + std::to_string(ttl));
            break;
        }
    }

    // --- cleanup everything
    if (raw_send_sock >= 0)
        ::close(raw_send_sock);
    ::close(tcp_recv_sock);
    icmp.close();

    // --- heuristic: only gateway + dest responded → ICMP11 blocked or NAT hell
    if (diag)
    {
        int responders = 0, first = -1, last = -1;
        for (auto &r : out)
            if (r.num_replies > 0)
            {
                responders++;
                if (first < 0)
                    first = r.ttl;
                last = r.ttl;
            }
        if (responders <= 2 && last <= 2)
        {
            diag->log("DIAG: Only local gateway and destination responded; "
                      "intermediate ICMP Time Exceeded likely blocked or not "
                      "translated by NAT/bridge.");
        }
    }

    return out;
}

} // namespace geo
