// ===================== File: src/tcp_probe.cpp =====================
#include "tcp_probe.hpp"
#include "dns_resolver.hpp"
#include "icmp_listener.hpp"
#include "utils_net.hpp"

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
#include "net_compat.hpp"
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace geo
{
    namespace
    {
        using clk = std::chrono::steady_clock;

        struct ProbeState
        {
            int ttl;
            clk::time_point t0;
            bool done = false;
        };

        static in_addr pick_ipv4(const std::vector<ResolvedAddress> &addrs)
        {
            for (const auto &ra : addrs)
                if (ra.family == AF_INET)
                    return reinterpret_cast<const sockaddr_in *>(&ra.addr)->sin_addr;
            throw std::runtime_error("Destination has no IPv4 address");
        }

        static in_addr find_local_ipv4_to(const in_addr &dst)
        {
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
            if (::getsockname(s, reinterpret_cast<sockaddr *>(&me), &len) < 0)
            {
                ::close(s);
                throw std::runtime_error("getsockname failed");
            }
            ::close(s);
            return me.sin_addr;
        }

        struct HopAgg
        {
            std::string ip;
            int count = 0;
            double min_ms = 0, max_ms = 0, sum_ms = 0;
            bool reached = false;
        };
        static std::string ip_to_string(uint32_t be_ip)
        {
            in_addr a;
            a.s_addr = be_ip;
            char buf[INET_ADDRSTRLEN];
            return inet_ntop(AF_INET, &a, buf, sizeof(buf)) ? std::string(buf) : std::string();
        }

    } // namespace

    std::vector<ProbeHopSummary>
    TcpProbe::trace(const std::string &host, int port, int max_hops, int timeout_ms,
                    SendMode mode, DiagLogger *diag)
    {
        auto addrs = DNSResolver::resolve(host, port);
        in_addr dst_ip = pick_ipv4(addrs);
        in_addr src_ip = find_local_ipv4_to(dst_ip);

        if (diag)
        {
            char dbuf[INET_ADDRSTRLEN], sbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dst_ip, dbuf, sizeof(dbuf));
            inet_ntop(AF_INET, &src_ip, sbuf, sizeof(sbuf));
            diag->log(std::string("SETUP src=") + sbuf + " dst=" + dbuf + ":" + std::to_string(port) +
                      " mode=" + (mode == SendMode::Raw ? "raw" : (mode == SendMode::Connect ? "connect" : "auto")));
        }

        // Receive sockets
        IcmpListener icmp;
        if (!icmp.open())
            throw std::runtime_error("Need CAP_NET_RAW/root for ICMP");
        int tcp_recv_sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (tcp_recv_sock < 0)
            throw std::runtime_error("Need CAP_NET_RAW/root to sniff TCP");

        // Optional raw sender
        int raw_send_sock = -1;
        if (mode == SendMode::Raw)
        {
            raw_send_sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if (raw_send_sock < 0)
                throw std::runtime_error("raw send socket failed");
            int on = 1;
            (void)setsockopt(raw_send_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
        }

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

            // ----- SEND 3 PROBES for this TTL -----
            struct ProbeSock
            {
                int fd;
            };
            std::unordered_map<uint16_t, ProbeSock> probe_socks; // used in Connect/Auto

            for (int i = 0; i < 3; ++i)
            {
                uint16_t sport = static_cast<uint16_t>(33434 + ttl * 3 + i);

                if (mode == SendMode::Raw)
                {
                    // RAW: craft minimal IP+TCP SYN
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
                    tcp->dest = htons(static_cast<uint16_t>(port));
                    tcp->seq = htonl((ttl << 24) | (i << 16) | 0x1234);
                    tcp->doff = 5;
                    TCP_SET_SYN(tcp, 1);
                    tcp->window = htons(65535);

                    // compute checksums (required in RAW mode)
                    // after filling ip and tcp headers:
                    ip->check = geo::net::ip_checksum(ip);
                    tcp->check = 0;
                    tcp->check = geo::net::tcp_checksum(ip, tcp, sizeof(tcphdr)); // add payload len if any

                    in_flight[sport] = ProbeState{ttl, clk::now(), false};
                    ssize_t rc = ::sendto(raw_send_sock, pkt.data(), pkt.size(), 0,
                                          reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
                    if (diag)
                    {
                        if (rc < 0)
                        {
                            diag->log(std::string("PROBE_SEND_ERR mode=raw ttl=") + std::to_string(ttl) +
                                      " idx=" + std::to_string(i) + " sport=" + std::to_string(sport) +
                                      " errno=" + std::to_string(errno) + " (" + std::strerror(errno) + ")");
                        }
                        else
                        {
                            diag->log("PROBE_SENT mode=raw ttl=" + std::to_string(ttl) +
                                      " idx=" + std::to_string(i) + " sport=" + std::to_string(sport) +
                                      " bytes=" + std::to_string(rc));
                        }
                    }
                }

                else
                { // Auto / Connect
                    int s = ::socket(AF_INET, SOCK_STREAM, 0);
                    if (s < 0)
                    {
                        if (diag)
                            diag->log("WARN socket() failed");
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

                    in_flight[sport] = ProbeState{ttl, clk::now(), false};
                    (void)::connect(s, reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
                    probe_socks[sport] = ProbeSock{s};

                    if (diag)
                        diag->log("PROBE_SENT mode=connect ttl=" + std::to_string(ttl) +
                                  " idx=" + std::to_string(i) + " sport=" + std::to_string(sport));
                }
            }

            // ----- WAIT for replies for this TTL -----
            auto deadline = clk::now() + std::chrono::milliseconds(timeout_ms);
            int replies_seen = 0;

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
                            double rtt = std::chrono::duration<double, std::milli>(clk::now() - it->second.t0).count();
                            if (agg.count == 0)
                                agg.ip = te->from_ip;
                            agg.count++;
                            if (agg.count == 1)
                            {
                                agg.min_ms = agg.max_ms = rtt;
                            }
                            else
                            {
                                agg.min_ms = std::min(agg.min_ms, rtt);
                                agg.max_ms = std::max(agg.max_ms, rtt);
                            }
                            agg.sum_ms += rtt;
                            it->second.done = true;
                            replies_seen++;

                            if (diag)
                                diag->log("ICMP_TIME_EXCEEDED from=" + te->from_ip +
                                          " sport=" + std::to_string(te->orig_sport) +
                                          " inner_ttl=" + std::to_string(te->orig_ttl) +
                                          " rtt_ms=" + std::to_string(rtt));
                        }
                        else
                        {
                            if (diag)
                                diag->log("ICMP_TIME_EXCEEDED (unmatched) sport=" + std::to_string(te->orig_sport));
                        }
                    }
                }

                // Destination (TCP RST or SYN+ACK)
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
                            if (it != in_flight.end() && !it->second.done && ip->saddr == dst_ip.s_addr)
                            {
                                bool synack = (TCP_IS_SYN(tcp) && TCP_IS_ACK(tcp));
                                bool rst    = TCP_IS_RST(tcp);
                                if (synack || rst)
                                {
                                    double rtt = std::chrono::duration<double, std::milli>(clk::now() - it->second.t0).count();
                                    std::string hop_ip = ip_to_string(ip->saddr);
                                    if (agg.count == 0)
                                        agg.ip = hop_ip;
                                    agg.count++;
                                    if (agg.count == 1)
                                    {
                                        agg.min_ms = agg.max_ms = rtt;
                                    }
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
                                    {
                                        diag->log(std::string("DEST_REPLY type=") + (synack ? "SYN-ACK" : "RST") +
                                                  " sport=" + std::to_string(dport) +
                                                  " rtt_ms=" + std::to_string(rtt));
                                    }

                                    // allow remaining replies for this hop; we'll stop after summarizing
                                    destination_reached = true;
                                }
                            }
                        }
                    }
                }
            }

            // close per-probe sockets (Connect/Auto)
            for (auto &kv : probe_socks)
            {
                if (kv.second.fd >= 0)
                    ::close(kv.second.fd);
            }

            // Summarize hop
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

        if (raw_send_sock >= 0)
            ::close(raw_send_sock);
        ::close(tcp_recv_sock);
        icmp.close();

        // Post-run heuristic: only gateway + destination responded → likely ICMP11 blocked / TTL mangled
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
                diag->log("DIAG: Only local gateway and destination responded; intermediate ICMP Time Exceeded likely blocked or not translated by NAT/bridge.");
            }
        }

        return out;
    }

} // namespace geo
