// ===================== include/ssl_session.hpp =====================
#pragma once
#include <string>
#include <openssl/ssl.h>

namespace geo
{
    class SslSession
    {
        SSL_CTX *ctx_;
        SSL *ssl_;

    public:
        SslSession();
        ~SslSession();

        bool handshake(int sockfd, const std::string &hostname);
        bool sendAll(const std::string &data) const;
        std::string recvAll() const;
    };
} // namespace geo