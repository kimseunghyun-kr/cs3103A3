

// ===================== src/parsed_url.cpp =====================
#include "parsed_url.hpp"

namespace geo
{
    ParsedURL::ParsedURL(const std::string &url)
    {
        scheme = "http"; // default
        path = "/";

        size_t scheme_end = url.find("://");
        size_t host_start = 0;
        if (scheme_end != std::string::npos)
        {
            scheme = url.substr(0, scheme_end);
            host_start = scheme_end + 3;
        }

        size_t path_start = url.find('/', host_start);
        if (path_start != std::string::npos)
        {
            host = url.substr(host_start, path_start - host_start);
            path = url.substr(path_start);
        }
        else
        {
            host = url.substr(host_start);
            path = "/";
        }
    }

    std::string ParsedURL::toGetRequestString() const
    {
        return std::string("GET ") + path + " HTTP/1.1\r\n" +
               "Host: " + host + "\r\n" +
               "Connection: close\r\n\r\n";
    }
} // namespace geo