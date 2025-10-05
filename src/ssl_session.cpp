// ===================== src/ssl_session.cpp =====================
#include "ssl_session.hpp"
#include <openssl/err.h>
#include <stdexcept>

namespace geo
{
    SslSession::SslSession() : ctx_(nullptr), ssl_(nullptr)
    {
        // OpenSSL 1.1+ auto-inits; these are no-ops/safe.
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        const SSL_METHOD *method = TLS_client_method();
        ctx_ = SSL_CTX_new(method);
        if (!ctx_)
            throw std::runtime_error("Failed to create SSL_CTX");
    }

    SslSession::~SslSession()
    {
        if (ssl_)
        {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (ctx_)
        {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

    bool SslSession::handshake(int sockfd, const std::string &hostname)
    {
        ssl_ = SSL_new(ctx_);
        if (!ssl_)
            return false;
        SSL_set_fd(ssl_, sockfd);
        SSL_set_tlsext_host_name(ssl_, hostname.c_str());
        if (SSL_connect(ssl_) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }
        return true;
    }

    bool SslSession::sendAll(const std::string &data) const
    {
        if (!ssl_)
            return false;
        int n = SSL_write(ssl_, data.c_str(), static_cast<int>(data.size()));
        return n == static_cast<int>(data.size());
    }

    std::string SslSession::recvAll() const
    {
        std::string response;
        response.reserve(8192);
        char buf[4096];
        while (true)
        {
            int bytes = SSL_read(ssl_, buf, sizeof(buf));
            if (bytes <= 0)
                break;
            response.append(buf, static_cast<size_t>(bytes));
        }
        return response;
    }
} // namespace geo