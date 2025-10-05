// main_trace.cpp
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "dns_resolver.hpp"
#include "geo_resolver.hpp"
#include "tcp_probe.hpp"

using namespace std;
using namespace geo;

static void print_usage(const char* argv0) {
    cerr << "Usage: " << argv0 << " <host> [port=443] [max_hops=30] [timeout_ms=1000]\n";
}

int main(int argc, char* argv[]) {
    ios::sync_with_stdio(false);

    if (argc < 2) { print_usage(argv[0]); return 1; }
    const string host      = argv[1];
    const int    port      = (argc >= 3 ? stoi(argv[2]) : 443);
    const int    max_hops  = (argc >= 4 ? stoi(argv[3]) : 30);
    const int    timeout_ms= (argc >= 5 ? stoi(argv[4]) : 1000);

    try {
        auto hops = TcpProbe::trace(host, port, max_hops, timeout_ms);

        cout << left  << setw(5)  << "Hop"
                     << setw(20) << "IP"
                     << setw(28) << "Location"
             << right << setw(12) << "min(ms)"
                     << setw(12) << "avg(ms)"
                     << setw(12) << "max(ms)" << "\n";
        cout << string(5+20+28+12+12+12, '-') << "\n";

        int reached_hop = -1;
        for (const auto& h : hops) {
            string ip  = h.hop_ip.empty() ? "*" : h.hop_ip;
            string loc = "";
            if (!h.hop_ip.empty()) {
                if (auto g = GeoResolver::lookup(h.hop_ip)) {
                    loc = g->city.empty() ? g->country : (g->city + ", " + g->country);
                }
            }

            cout << left  << setw(5)  << h.ttl
                         << setw(20) << ip.substr(0, 19)
                         << setw(28) << loc.substr(0, 27)
                 << right;

            if (h.num_replies == 0) {
                cout << setw(12) << "*" << setw(12) << "*" << setw(12) << "*" << "\n";
            } else {
                cout << setw(12) << fixed << setprecision(2) << h.rtt_min_ms
                     << setw(12) << fixed << setprecision(2) << h.rtt_avg_ms
                     << setw(12) << fixed << setprecision(2) << h.rtt_max_ms << "\n";
            }
            if (h.reached && reached_hop == -1) reached_hop = h.ttl;
        }

        if (reached_hop != -1) {
            cout << "\nDestination reached in " << reached_hop << " hops.\n";
        } else {
            cout << "\nDestination not reached within max hops.\n";
        }
        return 0;
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
