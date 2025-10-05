/**
 * # build just the tracer
 * make trace     # alias: make geo_trace
 * sudo ./bin/geo_trace cloudflare.com 443
 */

//// ===================== File: main.cpp =====================
/**
 * # build just the tracer
 * make trace     # alias: make geo_trace
 * sudo ./bin/geo_trace cloudflare.com 443
 *
 * Examples with options:
 *   sudo ./bin/geo_trace usp.ac.fj 443 30 2000 --mode=connect --log=diag_usp.txt
 *   sudo ./bin/geo_trace google.com --mode=raw --log=diag_raw.txt
 */

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <arpa/inet.h>

#include "dns_resolver.hpp"
#include "geo_resolver.hpp"
#include "tcp_probe.hpp"
#include "diag_logger.hpp"   // <-- added

using namespace std;
using namespace geo;

static void print_usage(const char *argv0) {
    cerr << "Usage:\n"
         << "  " << argv0 << " <host> [port=443] [max_hops=30] [timeout_ms=1000] [--mode=auto|connect|raw] [--log=PATH]\n"
         << "\nNotes:\n"
         << "  - Raw ICMP receive is required (needs sudo or CAP_NET_RAW).\n"
         << "  - --mode=connect mirrors traceroute -T and is NAT-friendly.\n"
         << "  - --mode=raw sends SYN via IP_HDRINCL (may fail behind NAT/VM).\n";
}

// ---- helpers for pretty output ----
static bool is_private_ipv4(const string &ip) {
    in_addr a{}; if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    uint32_t x = ntohl(a.s_addr);
    if ((x & 0xFF000000) == 0x0A000000) return true;        // 10.0.0.0/8
    if ((x & 0xFFF00000) == 0xAC100000) return true;        // 172.16.0.0/12
    if ((x & 0xFFFF0000) == 0xC0A80000) return true;        // 192.168.0.0/16
    if ((x & 0xFFC00000) == 0x64400000) return true;        // 100.64.0.0/10 (CGNAT)
    if ((x & 0xFFFF0000) == 0xA9FE0000) return true;        // 169.254.0.0/16 (link-local)
    return false;
}

static string make_desc(const optional<GeoInfo> &g, const string &ip) {
    if (is_private_ipv4(ip)) return "Local Router";
    if (!g) return "Unknown location";
    string loc;
    if (!g->city.empty() && !g->country.empty()) loc = g->city + ", " + g->country;
    else if (!g->country.empty()) loc = g->country;
    else loc = "Unknown location";

    string net;
    if (!g->org.empty()) net = g->org;
    else if (!g->isp.empty()) net = g->isp;
    else if (!g->as_name.empty()) net = g->as_name;
    if (!g->asn.empty()) { if (!net.empty()) net += ", "; net += g->asn; }
    if (!net.empty()) return loc + ", " + net;
    return loc;
}

static string pick_dest_ipv4(const string &host, int port) {
    auto addrs = DNSResolver::resolve(host, port);
    for (const auto &ra : addrs) {
        if (ra.family == AF_INET) {
            char buf[INET_ADDRSTRLEN];
            auto *sin = reinterpret_cast<const sockaddr_in *>(&ra.addr);
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) return string(buf);
        }
    }
    return string{};
}

static SendMode parse_mode(const string& s) {
    if (s == "auto")    return SendMode::Auto;
    if (s == "connect") return SendMode::Connect;
    if (s == "raw")     return SendMode::Raw;
    throw invalid_argument("bad mode: " + s);
}

int main(int argc, char *argv[]) {
    ios::sync_with_stdio(false);

    if (argc < 2) { print_usage(argv[0]); return 1; }

    // Parse flags in any position:
    //   positional: <host> [port] [max_hops] [timeout_ms]
    //   flags: --mode=auto|connect|raw , --log=PATH
    vector<string> pos;
    string log_path;
    SendMode mode = SendMode::Auto;

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a.rfind("--mode=", 0) == 0) {
            try { mode = parse_mode(a.substr(7)); }
            catch (const exception& e) { cerr << e.what() << "\n"; print_usage(argv[0]); return 1; }
        } else if (a.rfind("--log=", 0) == 0) {
            log_path = a.substr(6);
        } else {
            pos.push_back(a);
        }
    }

    if (pos.empty()) { print_usage(argv[0]); return 1; }

    const string host      = pos[0];
    const int    port      = (pos.size() >= 2 ? stoi(pos[1]) : 443);
    const int    max_hops  = (pos.size() >= 3 ? stoi(pos[2]) : 30);
    const int    timeout_ms= (pos.size() >= 4 ? stoi(pos[3]) : 1000);

    try {
        // Show destination IPv4
        string dst_ip = pick_dest_ipv4(host, port);
        if (!dst_ip.empty()) cout << "[Destination - " << dst_ip << "]\n";

        // Optional diagnostics
        DiagLogger diag(log_path);
        DiagLogger* dptr = (diag.ok() && !log_path.empty()) ? &diag : nullptr;
        if (!log_path.empty() && !diag.ok()) {
            cerr << "Warning: couldn't open log file: " << log_path << "\n";
        }

        // Trace with mode + diagnostics
        auto hops = TcpProbe::trace(host, port, max_hops, timeout_ms, mode, dptr);

        int reached_hop = -1;
        for (const auto &h : hops) {
            if (h.num_replies == 0) {
                cout << "Hop " << h.ttl
                     << ": * (no reply) - min/avg/max RTT = * / * / * ms\n";
                continue;
            }

            string ip = h.hop_ip;
            optional<GeoInfo> g;
            if (!ip.empty()) g = GeoResolver::lookup(ip);
            string desc = make_desc(g, ip);

            cout << "Hop " << h.ttl << ": " << ip
                 << " (" << desc << ") - min/avg/max RTT = "
                 << fixed << setprecision(2)
                 << h.rtt_min_ms << " / " << h.rtt_avg_ms << " / " << h.rtt_max_ms << " ms\n";

            if (h.reached && reached_hop == -1) reached_hop = h.ttl;
        }

        cout << string(43, '-') << '\n';
        if (reached_hop != -1) cout << "Total hops: " << reached_hop << '\n';
        else if (!hops.empty()) cout << "Total hops: " << hops.back().ttl << " (destination not reached)\n";

        return 0;
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
