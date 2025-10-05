//// ===================== File: src/tcp_probe.cpp =====================
#include "tcp_probe.hpp"
#include "dns_resolver.hpp"
#include "icmp_listener.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <map>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netinet/ip.h>
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

        static uint16_t checksum16(const void *data, size_t len)
        {
            uint32_t sum = 0;
            auto *p = reinterpret_cast<const uint16_t *>(data);
            while (len > 1)
            {
                sum += *p++;
                len -= 2;
            }
            if (len)
                sum += *reinterpret_cast<const uint8_t *>(p);
            while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return static_cast<uint16_t>(~sum);
        }

        static uint16_t tcp_checksum(const iphdr &ip, const tcphdr &tcp)
        {
            struct Pseudo
            {
                uint32_t src, dst;
                uint8_t z, proto;
                uint16_t len;
            } pseudo{};
            pseudo.src = ip.saddr;
            pseudo.dst = ip.daddr;
            pseudo.z = 0;
            pseudo.proto = IPPROTO_TCP;
            pseudo.len = htons(sizeof(tcphdr));
            std::array<uint8_t, sizeof(Pseudo) + sizeof(tcphdr)> buf{};
            std::memcpy(buf.data(), &pseudo, sizeof(Pseudo));
            std::memcpy(buf.data() + sizeof(Pseudo), &tcp, sizeof(tcphdr));
            return checksum16(buf.data(), buf.size());
        }

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
            char b[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &a, b, sizeof(b)))
                return "";
            return b;
        }
    }

    std::vector<ProbeHopSummary> TcpProbe::trace(const std::string &host, int port, int max_hops, int timeout_ms)
    {
        auto addrs = DNSResolver::resolve(host, port);
        in_addr dst_ip = pick_ipv4(addrs);
        in_addr src_ip = find_local_ipv4_to(dst_ip);

        int send_sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (send_sock < 0)
            throw std::runtime_error("Need CAP_NET_RAW/root to create raw send socket");
        int on = 1;
        if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
            throw std::runtime_error("setsockopt(IP_HDRINCL) failed");

        IcmpListener icmp;
        if (!icmp.open())
            throw std::runtime_error("Need CAP_NET_RAW/root to receive ICMP");
        int tcp_recv_sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (tcp_recv_sock < 0)
            throw std::runtime_error("Need CAP_NET_RAW/root to sniff TCP replies");

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

            // Send 3 probes for this TTL
            for (int i = 0; i < 3; ++i)
            {
                uint16_t sport = static_cast<uint16_t>(33434 + ttl * 3 + i);
                uint32_t seq = (static_cast<uint32_t>(ttl) << 24) | (static_cast<uint32_t>(i) << 16) | (0x1234 + i);

                std::array<uint8_t, sizeof(iphdr) + sizeof(tcphdr)> pkt{};
                auto *ip = reinterpret_cast<iphdr *>(pkt.data());
                auto *tcp = reinterpret_cast<tcphdr *>(pkt.data() + sizeof(iphdr));

                // IP header
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
                ip->check = checksum16(ip, sizeof(iphdr));
                // TCP header
                std::memset(tcp, 0, sizeof(tcphdr));
                tcp->source = htons(sport);
                tcp->dest = htons(static_cast<uint16_t>(port));
                tcp->seq = htonl(seq);
                tcp->doff = 5;
                tcp->syn = 1;
                tcp->window = htons(65535);
                tcp->check = 0;
                tcp->urg_ptr = 0;
                tcp->check = tcp_checksum(*ip, *tcp);

                in_flight[sport] = ProbeState{ttl, clk::now(), false};
                (void)::sendto(send_sock, pkt.data(), pkt.size(), 0, reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
            }

            auto deadline = clk::now() + std::chrono::milliseconds(timeout_ms);
            int replies_seen = 0;

            while (clk::now() < deadline && replies_seen < 3 && !destination_reached)
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
                timeval tv{static_cast<long>(remain.count() / 1000), static_cast<suseconds_t>((remain.count() % 1000) * 1000)};

                int rc = ::select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
                if (rc <= 0)
                    continue; // timeout or EINTR

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
                        }
                    }
                }

                if (FD_ISSET(tcp_recv_sock, &rfds))
                {
                    std::array<uint8_t, 2048> buf{};
                    sockaddr_in from{};
                    socklen_t flen = sizeof(from);
                    ssize_t n = ::recvfrom(tcp_recv_sock, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr *>(&from), &flen);
                    if (n <= 0)
                        continue;
                    auto *ip = reinterpret_cast<iphdr *>(buf.data());
                    size_t off = ip->ihl * 4;
                    if (off + sizeof(tcphdr) > static_cast<size_t>(n))
                        continue;
                    auto *tcp = reinterpret_cast<tcphdr *>(buf.data() + off);
                    uint16_t dport = ntohs(tcp->dest);
                    auto it = in_flight.find(dport);
                    if (it == in_flight.end() || it->second.done)
                        continue;
                    if (ip->saddr != dst_ip.s_addr)
                        continue; // only destination matters for reach
                    bool synack = (tcp->syn && tcp->ack);
                    bool rst = (tcp->rst != 0);
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
                        destination_reached = true;
                    }
                }
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
        }

        ::close(send_sock);
        ::close(tcp_recv_sock);
        icmp.close();
        return out;
    }
} // namespace geo