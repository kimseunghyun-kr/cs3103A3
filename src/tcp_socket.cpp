// ===================== src/tcp_socket.cpp =====================
#include "tcp_socket.hpp"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace geo
{
    TcpSocket::TcpSocket() : sockfd_(-1) {}
    TcpSocket::~TcpSocket() { closeSocket(); }

    void TcpSocket::closeSocket()
    {
        if (sockfd_ != -1)
        {
            ::close(sockfd_);
            sockfd_ = -1;
        }
    }

    bool TcpSocket::connectTo(const ResolvedAddress &ra)
    {
        sockfd_ = ::socket(ra.family, ra.socktype, ra.protocol);
        if (sockfd_ == -1)
            return false;
        if (::connect(sockfd_, reinterpret_cast<const sockaddr *>(&ra.addr), ra.addrlen) == 0)
            return true;
        ::close(sockfd_);
        sockfd_ = -1;
        return false;
    }

    bool TcpSocket::sendAll(const std::string &data) const
    {
        if (sockfd_ == -1){
            return false;
        }
        ssize_t n = ::send(sockfd_, data.c_str(), data.size(), 0);
        return n == static_cast<ssize_t>(data.size());
    }

    std::string TcpSocket::recvAll() const
    {
        std::string response;
        response.reserve(8192);
        char buf[4096];
        while (true)
        {
            ssize_t bytes = ::recv(sockfd_, buf, sizeof(buf), 0);
            if (bytes <= 0)
                break;
            response.append(buf, static_cast<size_t>(bytes));
        }
        return response;
    }
} // namespace geo