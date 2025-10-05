// ===================== include/tcp_socket.hpp =====================
#pragma once
#include <string>
#include "dns_resolver.hpp"

namespace geo
{
    class TcpSocket
    {
        int sockfd_;

    public:
        TcpSocket();
        ~TcpSocket();

        void closeSocket();
        bool connectTo(const ResolvedAddress &ra);
        bool sendAll(const std::string &data) const;
        std::string recvAll() const;
        int fd() const { return sockfd_; }
    };
} // namespace geo