//// ===================== File: src/geo_resolver.cpp =====================
#include "geo_resolver.hpp"
#include "dns_resolver.hpp"
#include "tcp_socket.hpp"

#include <arpa/inet.h>
#include <regex>
#include <string>

namespace geo {
// Very small HTTP client to ip-api.com (no HTTPS). Free tier is fine for traceroute volume.
// Example: GET /json/8.8.8.8?fields=status,country,city,lat,lon
static std::string http_get(const std::string& host, const std::string& path) {
    auto addrs = DNSResolver::resolve(host, 80);
    for (const auto& ra : addrs) {
        TcpSocket tcp;
        if (!tcp.connectTo(ra)) continue;
        std::string req = "GET " + path + " HTTP/1.1\r\n"
                  "Host: " + host + "\r\n"
                  "Connection: close\r\n"
                  "\r\n";

        if (!tcp.sendAll(req)) return {};
        return tcp.recvAll();
    }
    return {};
}

static std::string extract_body(const std::string& resp) {
    auto p = resp.find("\r\n\r\n");

    if (p == std::string::npos) return resp;
    return resp.substr(p + 4);
}

std::optional<GeoInfo> GeoResolver::lookup(const std::string& ip) {
    const std::string host = "ip-api.com";
    const std::string path = "/json/" + ip + "?fields=status,country,city,lat,lon";
    std::string resp = http_get(host, path);
    if (resp.empty()) return std::nullopt;
    std::string body = extract_body(resp);

    if (body.find("\"success\"") == std::string::npos && body.find("\"status\":\"success\"") == std::string::npos) {
        return std::nullopt;
    }

    GeoInfo g{}; g.ip = ip;
    std::smatch m;
    std::regex re_country("\"country\":\"([^\"]*)\"");
    std::regex re_city("\"city\":\"([^\"]*)\"");
    std::regex re_lat("\"lat\":([\-0-9.]+)");
    std::regex re_lon("\"lon\":([\-0-9.]+)");
    if (std::regex_search(body, m, re_country)) g.country = m[1];
    if (std::regex_search(body, m, re_city)) g.city = m[1];
    if (std::regex_search(body, m, re_lat)) g.lat = std::stod(m[1]);
    if (std::regex_search(body, m, re_lon)) g.lon = std::stod(m[1]);
    return g;
}
} // namespace geo