// ===================== main.cpp =====================
#include <iostream>
#include <regex>
#include <string>
#include <vector>

#include "parsed_url.hpp"
#include "dns_resolver.hpp"
#include "tcp_socket.hpp"
#include "ssl_session.hpp"

using namespace std;
using namespace geo;

static string extractPublicIP(const string &httpResponse)
{
    size_t header_end = httpResponse.find("\r\n\r\n");
    if (header_end == string::npos)
        return httpResponse; // malformed (no headers)

    string headers = httpResponse.substr(0, header_end);
    string body = httpResponse.substr(header_end + 4);

    if (headers.find("Transfer-Encoding: chunked") != string::npos)
    {
        string decoded;
        size_t pos = 0;
        while (pos < body.size())
        {
            size_t line_end = body.find("\r\n", pos);
            if (line_end == string::npos)
                break;
            string size_str = body.substr(pos, line_end - pos);
            int chunk_size = 0;
            try
            {
                chunk_size = stoi(size_str, nullptr, 16);
            }
            catch (...)
            {
                break;
            }
            pos = line_end + 2;
            if (chunk_size == 0)
                break;
            if (pos + chunk_size <= body.size())
                decoded.append(body.substr(pos, chunk_size));
            pos += chunk_size + 2; // skip CRLF
        }
        body = decoded;
    }

    body = regex_replace(body, regex("<[^>]*>"), "");

    regex ip_regex(R"((\d{1,3}(?:\.\d{1,3}){3}))");
    smatch match;
    if (regex_search(body, match, ip_regex))
    {
        return string("My public IP address is ") + match.str(1);
    }
    return body; // fallback: raw body
}

int main(int argc, char *argv[])
{
    ios::sync_with_stdio(false);

    if (argc < 2)
    {
        cerr << "Usage: " << argv[0] << " <url>\n";
        return 1;
    }

    const int HTTPS_PORT = 443;
    const int HTTP_PORT = 80;

    string input_url = argv[1];
    ParsedURL parsed(input_url);

    try
    {
        int port = (parsed.scheme == "https") ? HTTPS_PORT : HTTP_PORT;
        auto addrs = DNSResolver::resolve(parsed.host, port);

        TcpSocket tcp;
        bool connected = false;
        string resp;

        for (const auto &ra : addrs)
        {
            if (!tcp.connectTo(ra))
                continue;
            connected = true;

            const string req = parsed.toGetRequestString();

            if (parsed.scheme == "https")
            {
                SslSession tls;
                if (!tls.handshake(tcp.fd(), parsed.host))
                {
                    cerr << "TLS handshake failed\n";
                    return 1;
                }
                if (!tls.sendAll(req))
                {
                    cerr << "SSL send failed\n";
                    return 1;
                }
                resp = tls.recvAll();
            }
            else
            {
                if (!tcp.sendAll(req))
                {
                    cerr << "TCP send failed\n";
                    return 1;
                }
                resp = tcp.recvAll();
            }
            break; // we got one working address
        }

        if (!connected)
        {
            cerr << "Connect failed for all resolved addresses\n";
            return 1;
        }
        cout << extractPublicIP(resp) << "\n";
        return 0;
    }
    catch (const exception &e)
    {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}