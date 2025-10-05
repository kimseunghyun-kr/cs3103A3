//// ===================== File: src/geo_r.cpp =====================
#include "geo_resolver.hpp"
#include "dns_resolver.hpp"
#include "tcp_socket.hpp"

#include <arpa/inet.h>
#include <regex>
#include <string>

namespace geo
{
    // Very small HTTP client to ip-api.com (no HTTPS). Free tier is fine for traceroute volume.
    // Example: GET /json/8.8.8.8?fields=status,country,city,lat,lon
    static std::string http_get(const std::string &host, const std::string &path)
    {
        auto addrs = DNSResolver::resolve(host, 80);
        for (const auto &ra : addrs)
        {
            TcpSocket tcp;
            if (!tcp.connectTo(ra))
                continue;
            std::string req = "GET " + path + " HTTP/1.1\r\n"
                                              "Host: " +
                              host + "\r\n"
                                     "Connection: close\r\n"
                                     "\r\n";

            if (!tcp.sendAll(req))
                return {};
            return tcp.recvAll();
        }
        return {};
    }

    static std::string extract_body(const std::string &resp)
    {
        auto p = resp.find("\r\n\r\n");

        if (p == std::string::npos)
            return resp;
        return resp.substr(p + 4);
    }

    std::optional<GeoInfo> GeoResolver::lookup(const std::string &ip)
    {
        const std::string host = "ip-api.com";
        // include ASN/ISP/org fields
        const std::string path = "/json/" + ip + "?fields=status,country,city,lat,lon,isp,org,as,asname";
        std::string resp = http_get(host, path);
        if (resp.empty())
            return std::nullopt;
        std::string body = extract_body(resp);

        if (body.find("\"status\":\"success\"") == std::string::npos)
        {
            return std::nullopt;
        }

        GeoInfo g{};
        g.ip = ip;
        std::smatch m;
        auto grab = [&](const std::regex &re)
        { return std::regex_search(body, m, re) ? m[1].str() : std::string(); };

        g.country = grab(std::regex("\"country\":\"([^\"]*)\""));
        g.city = grab(std::regex("\"city\":\"([^\"]*)\""));
        std::string slat = grab(std::regex("\"lat\":([-0-9.]+)"));
        std::string slon = grab(std::regex("\"lon\":([-0-9.]+)"));
        if (!slat.empty())
            g.lat = std::stod(slat);
        if (!slon.empty())
            g.lon = std::stod(slon);
        g.isp = grab(std::regex("\"isp\":\"([^\"]*)\""));
        g.org = grab(std::regex("\"org\":\"([^\"]*)\""));
        g.as_text = grab(std::regex("\"as\":\"([^\"]*)\""));
        g.as_name = grab(std::regex("\"asname\":\"([^\"]*)\""));

        // Extract "ASnnnnn" prefix from as_text
        std::smatch am;
        if (std::regex_search(g.as_text, am, std::regex("(AS\\d+)")))
            g.asn = am[1];

        return g;
    }
} // namespace geo
