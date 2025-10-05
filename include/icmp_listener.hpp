

// ===================== include/icmp_listener.hpp =====================
#pragma once
#include <string>
#include <optional>


namespace geo {
struct IcmpPacketInfo {
std::string src_ip;
int ttl{};
};


class IcmpListener {
public:
bool open(); // may require CAP_NET_RAW/root on Linux
void close();
std::optional<IcmpPacketInfo> recv_one(int timeout_ms);
};
} // namespace geo