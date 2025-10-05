/**
 * how to compile
 * srun g++ -std=c++17 tcp_client.cpp -o tcp_client -lssl -lcrypto
 *
 * how to run
 * ./tcp_client https://varlabs.comp.nus.edu.sg/tools/yourip.php
*/

#include <iostream>     // cout, //cerr
#include <string>       // string
#include <vector>       // vector
#include <stdexcept>    // runtime_error
#include <cstring>      // memcpy
#include <regex>

#include <sys/types.h>   // basic system data types
#include <sys/socket.h>  // socket(), connect(), send(), recv()
#include <netdb.h>       // getaddrinfo(), freeaddrinfo(), gai_strerror()
#include <arpa/inet.h>   // inet_ntop(), inet_pton()
#include <unistd.h>      // close()
#include <errno.h>       // errno, strerror()

#include <openssl/ssl.h>
#include <openssl/err.h>

constexpr int HTTPS_PORT = 443;
constexpr int HTTP_PORT = 80;

using namespace std;

class ParsedURL {
public:
    string scheme;  // "http" ::  "https"
    string host;    // "varlabs.comp.nus.edu.sg"
    string path;    // "/tools/yourip.php"

    // Constructor from a URL string
    explicit ParsedURL(const string &url) {
        scheme = "http"; // default
        path = "/";

        // Find scheme
        size_t scheme_end = url.find("://");
        size_t host_start = 0;
        if (scheme_end != string::npos) {
            scheme = url.substr(0, scheme_end);
            host_start = scheme_end + 3;
        }

        // Find path
        size_t path_start = url.find('/', host_start);
        if (path_start != string::npos) {
            host = url.substr(host_start, path_start - host_start);
            path = url.substr(path_start);
        } else {
            host = url.substr(host_start);
            path = "/";
        }
    }

    // Generate a GET request string
    string toGetRequestString() const {
        return "GET " + path + " HTTP/1.1\r\n"
               "Host: " + host + "\r\n"
               "Connection: close\r\n\r\n";
    }
};

// Remove HTTP headers + decode chunked transfer + extract IP
string extractPublicIP(const string &httpResponse) {
    // Split headers from body
    size_t header_end = httpResponse.find("\r\n\r\n");
    if (header_end == string::npos) return httpResponse; // malformed
    string headers = httpResponse.substr(0, header_end);
    string body = httpResponse.substr(header_end + 4);

    // Handle Transfer-Encoding: chunked
    if (headers.find("Transfer-Encoding: chunked") != string::npos) {
        string decoded;
        size_t pos = 0;
        while (pos < body.size()) {
            size_t line_end = body.find("\r\n", pos);
            if (line_end == string::npos) break;

            string size_str = body.substr(pos, line_end - pos);
            int chunk_size = stoi(size_str, nullptr, 16);
            if (chunk_size == 0) break;

            pos = line_end + 2;
            if (pos + chunk_size <= body.size()) {
                decoded.append(body.substr(pos, chunk_size));
            }
            pos += chunk_size + 2;
        }
        body = decoded;
    }

    // Strip possible <body> or HTML tags (basic)
    body = regex_replace(body, regex("<[^>]*>"), "");

    // Extract IP address pattern
    regex ip_regex(R"((\d{1,3}(\.\d{1,3}){3}))");
    smatch match;
    if (regex_search(body, match, ip_regex)) {
        return "My public IP address is " + match.str(1);
    }

    // Fallback: just return cleaned body
    return body;
}

class DNSResolver {
public:
    struct ResolvedAddress {
        int family;
        int socktype;
        int protocol;
        sockaddr_storage addr;
        socklen_t addrlen;
    };

    static vector<ResolvedAddress> resolve(const string &host, int port) {
        vector<ResolvedAddress> results;
        addrinfo hints{}, *res;
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        string portStr = to_string(port);
        int status = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
        if (status != 0) {
            throw runtime_error("DNS resolution failed for " + host +
                                ": " + gai_strerror(status));
        }

        for (auto *p = res; p != nullptr; p = p->ai_next) {
            ResolvedAddress ra;
            ra.family   = p->ai_family;
            ra.socktype = p->ai_socktype;
            ra.protocol = p->ai_protocol;
            ra.addrlen  = p->ai_addrlen;
            memcpy(&ra.addr, p->ai_addr, p->ai_addrlen);
            results.push_back(ra);
        }

        freeaddrinfo(res);
        return results;
    }
};

class TcpSocket {
    int sockfd;

public:
    TcpSocket() : sockfd(-1) {}
    ~TcpSocket() { closeSocket(); }

    void closeSocket() {
        if (sockfd != -1) {
            close(sockfd);
            sockfd = -1;
        }
    }

    bool connectTo(const DNSResolver::ResolvedAddress &ra) {
        sockfd = socket(ra.family, ra.socktype, ra.protocol);
        if (sockfd == -1) return false;

        if (::connect(sockfd, (sockaddr*)&ra.addr, ra.addrlen) == 0) {
            return true; // success
        }

        close(sockfd);
        sockfd = -1;
        return false;
    }

    bool sendAll(const string &data) {
        return send(sockfd, data.c_str(), data.size(), 0) == (ssize_t)data.size();
    }

    string recvAll() {
        string response;
        char buf[4096];
        int bytes;
        while ((bytes = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
            response.append(buf, bytes);
        }
        return response;
    }

    int getFd() const { return sockfd; }
};


class SslSession {
    SSL_CTX* ctx;
    SSL* ssl;

public:
    // Apparently i read the old docs.. 
    // In modern OpenSSL (1.1.0+), ALL OF THIS IS POINTLESS because there is auto-init
    // OPENSSL_init_ssl()
    // ngl i really should have used python ffs.
    SslSession() : ctx(nullptr), ssl(nullptr) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
	
	// note that this "method" decides which TLS versions we are going to support.
	// SSLv23_client_method() was in the docs -> rlly.
        const SSL_METHOD* method = TLS_client_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) throw runtime_error("Failed to create SSL_CTX");
    }

    // ngl this macro quite nice for teardown'
    // thanks juan carlo
    ~SslSession() {
        if (ssl) {
	// got SSL routines:ssl3_read_bytes:sslv3 alert bad record mac from doing  just close() the socket.
        // Proper shutdown requires:
        //   1. send "close_notify" alert (SSL_shutdown)
        //   2. nuke the session (SSL_free)
        //   3. nuke the context (SSL_CTX_free)
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (ctx) SSL_CTX_free(ctx);
    }

    bool handshake(const TcpSocket &sock, const string &hostname) {
        // set the new ssl context 
	ssl = SSL_new(ctx);
	// context set failed. something went wrong during handshake
        if (!ssl) return false;
	
	// the file descriptor thing mentioned during lecture. legacy? was it?
        SSL_set_fd(ssl, sock.getFd());

        // Enable SNI (Server Name Indication)
        SSL_set_tlsext_host_name(ssl, hostname.c_str());
	
	// attempt the actual ssl 
        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        return true;
    }

    bool sendAll(const string &data) {
	//same thing as the socket write, just encoded with session key from ssl
        return SSL_write(ssl, data.c_str(), data.size()) == (ssize_t)data.size();
    }

    string recvAll() {
	//same thing as the socket response
        string response;
        char buf[4096];
        int bytes;
        while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            response.append(buf, bytes);
        }
        return response;
    }
};

int main(int argc, char* argv[]) {
    ios::sync_with_stdio(false);

    if (argc < 2) {
        //cerr << "Usage: " << argv[0] << " <url>\n";
        return 1;
    }

    string input_url = argv[1];
    ParsedURL parsed(input_url);

    //cerr << "DEBUG: scheme=" << parsed.scheme 
        // << " host=" << parsed.host 
        // << " path=" << parsed.path << endl;

    try {
        int port = (parsed.scheme == "https") ? HTTPS_PORT : HTTP_PORT;
        //cerr << "DEBUG: chosen port=" << port << endl;

        auto addrs = DNSResolver::resolve(parsed.host, port);
        //cerr << "DEBUG: resolved " << addrs.size() << " addresses for host=" << parsed.host << endl;

        bool connected = false;
        string resp;

        TcpSocket tcp;
        for (auto &ra : addrs) {
            //cerr << "DEBUG: trying to connect... family=" << ra.family
                 //<< " socktype=" << ra.socktype
                 //<< " proto=" << ra.protocol << endl;

            if (tcp.connectTo(ra)) {
               // cout << "Connected to " << parsed.host << " on port " << port << "\n";
                connected = true;

                string req = parsed.toGetRequestString();
                //cerr << "DEBUG: request string built:\n" << req << endl;

                if (parsed.scheme == "https") {
                    //cerr << "DEBUG: starting TLS handshake..." << endl;
                    SslSession tls;
                    if (!tls.handshake(tcp, parsed.host)) {
                        //cerr << "TLS handshake failed\n";
                        return 1;
                    }
                    //cerr << "DEBUG: TLS handshake success" << endl;

                    tls.sendAll(req);
                    //cerr << "DEBUG: request sent over SSL" << endl;

                    resp = tls.recvAll();
                    //cerr << "DEBUG: received " << resp.size() << " bytes (SSL)" << endl;
                } else {
                    //cerr << "DEBUG: sending plain HTTP request" << endl;
                    tcp.sendAll(req);

                    resp = tcp.recvAll();
                    //cerr << "DEBUG: received " << resp.size() << " bytes (plain TCP)" << endl;
                }

                break;
            } else {
                //cerr << "DEBUG: connect attempt failed, trying next address..." << endl;
            }
        }

        if (!connected) {
            //cerr << "Failed to connect\n";
            return 1;
        }

        //cerr << "DEBUG: starting response extraction" << endl;
        cout << extractPublicIP(resp) << endl;

    } catch (const exception &e) {
        //cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}